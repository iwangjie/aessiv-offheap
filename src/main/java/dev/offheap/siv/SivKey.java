package dev.offheap.siv;

import java.io.IOException;
import javax.crypto.AEADBadTagException;

/**
 * AES-SIV (RFC 5297) with the key material living outside the Java heap.
 *
 * <p>What is secret here: the two AES key schedules and the CMAC subkeys derived from them. All of it
 * is native memory, zeroed by {@link #close()}. What is not: the plaintext and ciphertext arrays the
 * caller passes in and gets back - those are the caller's data, and keeping them on the heap is what
 * makes this usable from ordinary Java code.
 *
 * <p>A key is split per RFC 5297 section 2.6: the left half drives S2V (CMAC), the right half drives
 * CTR. The raw key region is zeroed as soon as both schedules exist, so after construction the only
 * representation of the key in the process is the expanded schedule.
 *
 * <p>Instances are immutable: every operation allocates its own native scratch and closes it, so one
 * {@code SivKey} can be shared across threads without synchronization. SIV is deterministic, so
 * identical AD sets and plaintexts produce identical output - use {@link #sealWithNonce} when that
 * matters.
 */
public final class SivKey implements Aead {

    /** Minimum key size: AES-128-SIV (RFC 5297 section 6.1). */
    public static final int MIN_KEY_BYTES = 32;
    /** Maximum key size: AES-256-SIV (RFC 5297 section 6.3). */
    public static final int MAX_KEY_BYTES = 64;

    private static final int BLOCK = 16;
    private static final int MAX_AD = 126;

    private final int keyBytes;
    private final AesBlockCipher s2vCipher;
    private final AesBlockCipher ctrCipher;
    private final NativeBuffer cmacSubkeys;
    private final Object lifecycle = new Object();
    private boolean destroyed;

    private SivKey(NativeBuffer rawKey) {
        int keyBytes = rawKey.size();
        checkKeyLength(keyBytes);
        int half = keyBytes / 2;
        AesBlockCipher s2v = null;
        AesBlockCipher ctr = null;
        NativeBuffer subkeys = null;
        try {
            s2v = new AesBlockCipher(rawKey, 0, half);
            ctr = new AesBlockCipher(rawKey, half, half);
            subkeys = deriveSubkeys(s2v);
        } catch (RuntimeException | Error e) {
            if (subkeys != null) {
                subkeys.close();
            }
            if (ctr != null) {
                ctr.close();
            }
            if (s2v != null) {
                s2v.close();
            }
            throw e;
        } finally {
            // Only the expanded schedules may exist from here on.
            rawKey.close();
        }
        this.keyBytes = keyBytes;
        this.s2vCipher = s2v;
        this.ctrCipher = ctr;
        this.cmacSubkeys = subkeys;
    }

    /** AES-128-SIV key from the kernel CSPRNG; the bytes are born in native memory. */
    public static SivKey generate() throws IOException {
        return generate(MIN_KEY_BYTES);
    }

    public static SivKey generate(int keyBytes) throws IOException {
        checkKeyLength(keyBytes);
        return importKey(OffHeapKey.random(keyBytes));
    }

    public static SivKey fromFile(java.nio.file.Path file) throws IOException {
        return importKey(OffHeapKey.fromFile(file));
    }

    /**
     * Takes ownership of {@code key}: the region is moved, not copied, expanded into round keys, and
     * zeroed before this method returns. The handle is dead afterwards.
     */
    public static SivKey importKey(OffHeapKey key) {
        return new SivKey(key.transfer());
    }

    /** Imports heap-resident key bytes. The caller's array is left untouched by design. */
    public static SivKey importKey(byte[] key) {
        return importKey(OffHeapKey.importFrom(key));
    }

    public int keyBytes() {
        return keyBytes;
    }

    // ---------------------------------------------------------------- seal / open

    /** {@code Z = V || C}: the deterministic form of RFC 5297. */
    public byte[] seal(byte[][] ad, byte[] plaintext) {
        return sealInternal(null, ad, plaintext);
    }

    /** 0: a null nonce is accepted, because RFC 5297 has a deterministic form. */
    @Override
    public int nonceBytes() {
        return 0;
    }

    /** Dispatch is explicit: a non-null nonce selects the RFC 5297 nonce variant, not a no-op. */
    @Override
    public byte[] seal(byte[] nonce, byte[][] ad, byte[] plaintext) {
        return sealInternal(nonce, ad, plaintext);
    }

    @Override
    public byte[] open(byte[] nonce, byte[][] ad, byte[] ivAndCiphertext)
            throws AEADBadTagException {
        return openInternal(nonce, ad, ivAndCiphertext);
    }

    /**
     * Nonce-based AES-SIV: the nonce becomes the last component of the S2V input vector (RFC 5297
     * section 2.6), so repeated plaintexts under distinct nonces are indistinguishable, while the
     * construction stays deterministic given the nonce.
     */
    public byte[] sealWithNonce(byte[] nonce, byte[][] ad, byte[] plaintext) {
        if (nonce == null) {
            throw new NullPointerException("nonce");
        }
        return sealInternal(nonce, ad, plaintext);
    }

    public byte[] open(byte[][] ad, byte[] ivAndCiphertext) throws AEADBadTagException {
        return openInternal(null, ad, ivAndCiphertext);
    }

    public byte[] openWithNonce(byte[] nonce, byte[][] ad, byte[] ivAndCiphertext)
            throws AEADBadTagException {
        if (nonce == null) {
            throw new NullPointerException("nonce");
        }
        return openInternal(nonce, ad, ivAndCiphertext);
    }

    private byte[] sealInternal(byte[] nonce, byte[][] ad, byte[] plaintext) {
        checkUsable();
        checkAd(ad);
        if (plaintext == null) {
            throw new NullPointerException("plaintext");
        }
        int ptLen = plaintext.length;
        try (Scratch s = new Scratch()) {
            NativeBuffer work = s.buffer(0, Math.max(1, ptLen));
            work.copyFrom(plaintext, 0, 0, ptLen);
            s2v(s, nonce, ad, work, ptLen);
            byte[] out = new byte[BLOCK + ptLen];
            s.iv.copyTo(out, 0, 0, BLOCK);
            ctr(s.iv, work, ptLen);
            work.copyTo(out, BLOCK, 0, ptLen);
            return out;
        }
    }

    private byte[] openInternal(byte[] nonce, byte[][] ad, byte[] ivAndCiphertext)
            throws AEADBadTagException {
        checkUsable();
        checkAd(ad);
        if (ivAndCiphertext == null) {
            throw new NullPointerException("ivAndCiphertext");
        }
        if (ivAndCiphertext.length < BLOCK) {
            throw new AEADBadTagException("input shorter than the 16-byte synthetic IV");
        }
        int ctLen = ivAndCiphertext.length - BLOCK;
        try (Scratch s = new Scratch()) {
            NativeBuffer receivedIv = s.buffer(1, BLOCK);
            NativeBuffer work = s.buffer(0, Math.max(1, ctLen));
            receivedIv.copyFrom(ivAndCiphertext, 0, 0, BLOCK);
            work.copyFrom(ivAndCiphertext, BLOCK, 0, ctLen);
            ctr(receivedIv, work, ctLen);
            s2v(s, nonce, ad, work, ctLen);
            if (!s.iv.equalsConstantTime(receivedIv)) {
                work.zero(0, ctLen);
                throw new AEADBadTagException("AES-SIV authentication tag mismatch");
            }
            byte[] out = new byte[ctLen];
            work.copyTo(out, 0, 0, ctLen);
            return out;
        }
    }

    // ---------------------------------------------------------------- S2V

    /**
     * S2V over {@code ad[*]} then {@code nonce} (if any) then the plaintext staged off-heap as
     * {@code work[0..len)}. The synthetic IV lands in {@code s.iv}; no intermediate keyed value ever
     * reaches the heap.
     */
    private void s2v(Scratch s, byte[] nonce, byte[][] ad, NativeBuffer work, int len) {
        Cmac cmac = s.cmac;
        NativeBuffer mac = s.mac;

        // D = CMAC(K1, <zero>)
        cmac.reset();
        cmac.updateZeros(BLOCK);
        cmac.finishInto(mac, 0);

        if (ad != null) {
            for (byte[] component : ad) {
                cmac.reset();
                cmac.update(component, 0, component.length);
                cmac.finishInto(s.tag, 0);
                Cmac.dblInPlace(mac, 0);
                mac.xorBlock16(0, s.tag, 0);
            }
        }
        if (nonce != null) {
            cmac.reset();
            cmac.update(nonce, 0, nonce.length);
            cmac.finishInto(s.tag, 0);
            Cmac.dblInPlace(mac, 0);
            mac.xorBlock16(0, s.tag, 0);
        }

        // T = Sn xorend D when the final component is a whole block, else T = dbl(D) xor pad(Sn).
        cmac.reset();
        if (len >= BLOCK) {
            NativeBuffer last = s.buffer(2, len);
            last.copyFrom(work, 0, 0, len);
            // xorend D: only the trailing block touches the running value.
            last.xorBlock16(len - BLOCK, mac, 0);
            cmac.update(last, 0, len);
        } else {
            NativeBuffer padded = s.tag;
            padded.zero(0, BLOCK);
            padded.copyFrom(work, 0, 0, len);
            padded.put(len, (byte) 0x80);
            Cmac.dblInPlace(mac, 0);
            padded.xorBlock16(0, mac, 0);
            cmac.update(padded, 0, BLOCK);
        }
        cmac.finishInto(s.iv, 0);
        mac.zero(0, BLOCK);
    }

    // ---------------------------------------------------------------- CTR

    /**
     * AES-CTR in place over {@code buf[0..length)}, starting at {@code initialCounter}.
     *
     * <p>RFC 5297 clears bit 63 and bit 31 of the counter so a 32-bit increment cannot carry into the
     * salt; with big-endian byte order those are the top bits of bytes 8 and 12.
     */
    private void ctr(NativeBuffer initialCounter, NativeBuffer buf, int length) {
        NativeBuffer counter = NativeBuffer.allocate(BLOCK);
        NativeBuffer keystream = NativeBuffer.allocate(BLOCK);
        try {
            counter.copyFrom(initialCounter, 0, 0, BLOCK);
            counter.put(8, (byte) (counter.get(8) & 0x7F));
            counter.put(12, (byte) (counter.get(12) & 0x7F));
            for (int offset = 0; offset < length; offset += BLOCK) {
                ctrCipher.encryptBlock(counter, 0, keystream, 0);
                buf.xorKeystream(offset, keystream, Math.min(BLOCK, length - offset));
                incrementCounter(counter);
            }
        } finally {
            keystream.close();
            counter.close();
        }
    }

    /** Adds one to the low 32 bits (big-endian) of a counter block. */
    private static void incrementCounter(NativeBuffer counter) {
        for (int i = BLOCK - 1; i >= 12; i--) {
            int b = (counter.get(i) & 0xFF) + 1;
            counter.put(i, (byte) b);
            if (b <= 0xFF) {
                return;
            }
        }
    }

    // ---------------------------------------------------------------- lifecycle

    private void checkUsable() {
        synchronized (lifecycle) {
            if (destroyed) {
                throw new IllegalStateException("key destroyed");
            }
        }
    }

    private static void checkKeyLength(int keyBytes) {
        if (keyBytes < MIN_KEY_BYTES || keyBytes > MAX_KEY_BYTES || keyBytes % 16 != 0) {
            throw new IllegalArgumentException("AES-SIV key must be 32, 48 or 64 bytes: " + keyBytes);
        }
    }

    private static void checkAd(byte[][] ad) {
        if (ad != null && ad.length > MAX_AD) {
            throw new IllegalArgumentException("at most " + MAX_AD + " AD components: " + ad.length);
        }
    }

    /** {@code E(K1, 0)} doubled twice: the RFC 4493 subkeys for the S2V half. */
    private static NativeBuffer deriveSubkeys(AesBlockCipher s2v) {
        NativeBuffer subkeys = NativeBuffer.allocate(2 * BLOCK);
        NativeBuffer tmp = NativeBuffer.allocate(BLOCK);
        NativeBuffer zeros = NativeBuffer.allocate(BLOCK);
        try {
            s2v.encryptBlock(zeros, 0, tmp, 0);
            subkeys.copyFrom(tmp, 0, 0, BLOCK);
            Cmac.dblInPlace(subkeys, 0);
            tmp.copyFrom(subkeys, 0, 0, BLOCK);
            Cmac.dblInPlace(tmp, 0);
            subkeys.copyFrom(tmp, 0, BLOCK, BLOCK);
            return subkeys;
        } catch (RuntimeException | Error e) {
            subkeys.close();
            throw e;
        } finally {
            tmp.close();
            zeros.close();
        }
    }

    /** Zeroes every key-dependent region. Idempotent; further use throws. */
    @Override
    public void close() {
        synchronized (lifecycle) {
            if (destroyed) {
                return;
            }
            destroyed = true;
        }
        cmacSubkeys.close();
        ctrCipher.close();
        s2vCipher.close();
    }

    @Override
    public String toString() {
        return "SivKey[" + (destroyed ? "destroyed" : keyBytes + "B") + "]";
    }

    /**
     * Per-operation native scratch. Keeping it out of the instance is what makes {@link SivKey}
     * shareable across threads and keeps concurrent operations from corrupting each other's tag.
     *
     * <p>Slots hold: 0 = plaintext/ciphertext copy, 1 = received IV, 2 = S2V final component.
     * {@code tag} is the 16-byte CMAC output, {@code mac} the running S2V {@code D} value.
     */
    private final class Scratch implements AutoCloseable {

        private final NativeBuffer[] slots = new NativeBuffer[3];
        private final Cmac cmac;
        private final NativeBuffer mac;
        private final NativeBuffer iv;
        private final NativeBuffer tag;

        Scratch() {
            cmac = new Cmac(s2vCipher, cmacSubkeys);
            mac = NativeBuffer.allocate(BLOCK);
            iv = NativeBuffer.allocate(BLOCK);
            tag = NativeBuffer.allocate(BLOCK);
        }

        /** Lazily sized slot, so an operation only pays for the buffers it needs. */
        NativeBuffer buffer(int slot, int size) {
            if (slots[slot] == null || slots[slot].size() < size) {
                if (slots[slot] != null) {
                    slots[slot].close();
                }
                slots[slot] = NativeBuffer.allocate(size);
            }
            return slots[slot];
        }

        @Override
        public void close() {
            for (int i = 0; i < slots.length; i++) {
                if (slots[i] != null) {
                    slots[i].close();
                    slots[i] = null;
                }
            }
            tag.close();
            iv.close();
            mac.close();
            cmac.close();
        }
    }
}
