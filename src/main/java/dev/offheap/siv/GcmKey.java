package dev.offheap.siv;

import java.io.IOException;
import javax.crypto.AEADBadTagException;

/**
 * AES-GCM (NIST SP 800-38D) with the AES key schedule held outside the Java heap.
 *
 * <p>Same key discipline as {@link SivKey}: the round keys and the GHASH subkey {@code H} (which is
 * {@code E(K, 0^128)}, i.e. key material) live in native memory and are zeroed by {@link #close()}.
 * There is no {@code byte[]}, {@code SecretKeySpec} or {@code String} holding key bytes anywhere.
 *
 * <p>GCM is not a drop-in replacement for SIV:
 *
 * <table>
 *   <caption>the differences that bite</caption>
 *   <tr><th></th><th>GCM</th><th>SIV</th></tr>
 *   <tr><td>nonce</td><td>mandatory, unique per key</td><td>optional (deterministic form)</td></tr>
 *   <tr><td>nonce reuse</td><td>releases {@code P1 xor P2} and allows tag forgery</td>
 *       <td>the deterministic form has no nonce to reuse</td></tr>
 *   <tr><td>output</td><td>{@code C || T}</td><td>{@code V || C}</td></tr>
 *   <tr><td>hardware</td><td>AES-NI + PCLMULQDQ path exists in the JDK</td><td>none</td></tr>
 * </table>
 *
 * <p>Instances are immutable - each operation allocates its own native scratch - so one key can be
 * shared across threads without synchronization.
 */
public final class GcmKey implements Aead {

    public static final int MIN_KEY_BYTES = 16;
    public static final int MAX_KEY_BYTES = 32;

    private static final int BLOCK = 16;
    private static final int TAG_BYTES = 16;
    /** SP 800-38D 5.2.1.1: a 96-bit IV is the native GCM size; anything else needs GHASH on the IV. */
    private static final int IV_BYTES = 12;

    private final int keyBytes;
    private final AesBlockCipher cipher;
    private final NativeBuffer h;
    private final Object lifecycle = new Object();
    private boolean destroyed;

    private GcmKey(NativeBuffer rawKey) {
        int keyBytes = rawKey.size();
        checkKeyLength(keyBytes);
        AesBlockCipher expanded = null;
        NativeBuffer subkey = null;
        try {
            expanded = new AesBlockCipher(rawKey, 0, keyBytes);
            subkey = deriveH(expanded);
        } catch (RuntimeException | Error e) {
            if (subkey != null) {
                subkey.close();
            }
            if (expanded != null) {
                expanded.close();
            }
            throw e;
        } finally {
            // Only the expanded schedule may exist from here on.
            rawKey.close();
        }
        this.keyBytes = keyBytes;
        this.cipher = expanded;
        this.h = subkey;
    }

    /** AES-256-GCM key from the kernel CSPRNG. */
    public static GcmKey generate() throws IOException {
        return generate(MAX_KEY_BYTES);
    }

    public static GcmKey generate(int keyBytes) throws IOException {
        checkKeyLength(keyBytes);
        return importKey(OffHeapKey.random(keyBytes));
    }

    public static GcmKey fromFile(java.nio.file.Path file) throws IOException {
        return importKey(OffHeapKey.fromFile(file));
    }

    /**
     * Takes ownership of {@code key}: the region is moved, expanded into round keys, and zeroed
     * before this method returns. The handle is dead afterwards.
     */
    public static GcmKey importKey(OffHeapKey key) {
        return new GcmKey(key.transfer());
    }

    /** Imports heap-resident key bytes. The caller's array is left untouched by design. */
    public static GcmKey importKey(byte[] key) {
        checkKeyLength(key.length);
        return importKey(OffHeapKey.importFrom(key));
    }

    public int keyBytes() {
        return keyBytes;
    }

    // ---------------------------------------------------------------- seal / open

    /** AES-GCM has no deterministic form: every call needs a fresh 96-bit nonce. */
    @Override
    public int nonceBytes() {
        return IV_BYTES;
    }

    /**
     * Returns {@code C || T} for a 96-bit {@code iv}.
     *
     * <p>The nonce must never repeat under one key: reuse releases {@code P1 xor P2} and lets an
     * attacker forge tags. Draw it from a CSPRNG or from a counter persisted alongside the key.
     */
    @Override
    public byte[] seal(byte[] iv, byte[][] ad, byte[] plaintext) {
        checkUsable();
        checkIv(iv);
        if (plaintext == null) {
            throw new NullPointerException("plaintext");
        }
        int ptLen = plaintext.length;
        try (Scratch s = new Scratch()) {
            NativeBuffer work = s.buffer(0, Math.max(1, ptLen));
            work.copyFrom(plaintext, 0, 0, ptLen);
            ctr(s, iv, work, ptLen);
            // GHASH covers the ciphertext, which is why it is computed after the CTR pass.
            authenticate(s, iv, ad, work, ptLen);
            byte[] out = new byte[ptLen + TAG_BYTES];
            work.copyTo(out, 0, 0, ptLen);
            s.tag.copyTo(out, ptLen, 0, TAG_BYTES);
            return out;
        }
    }

    /** Authenticates {@code C || T} and returns the plaintext; nothing is returned unless the tag holds. */
    @Override
    public byte[] open(byte[] iv, byte[][] ad, byte[] ciphertextAndTag)
            throws AEADBadTagException {
        checkUsable();
        checkIv(iv);
        if (ciphertextAndTag == null) {
            throw new NullPointerException("ciphertextAndTag");
        }
        if (ciphertextAndTag.length < TAG_BYTES) {
            throw new AEADBadTagException("input shorter than the 16-byte tag");
        }
        int ctLen = ciphertextAndTag.length - TAG_BYTES;
        try (Scratch s = new Scratch()) {
            NativeBuffer work = s.buffer(0, Math.max(1, ctLen));
            NativeBuffer receivedTag = s.buffer(1, TAG_BYTES);
            work.copyFrom(ciphertextAndTag, 0, 0, ctLen);
            receivedTag.copyFrom(ciphertextAndTag, ctLen, 0, TAG_BYTES);
            // Verify before decrypting: an unauthenticated plaintext must never be released.
            authenticate(s, iv, ad, work, ctLen);
            if (!s.tag.equalsConstantTime(receivedTag)) {
                work.zero(0, ctLen);
                throw new AEADBadTagException("AES-GCM authentication tag mismatch");
            }
            ctr(s, iv, work, ctLen);
            byte[] out = new byte[ctLen];
            work.copyTo(out, 0, 0, ctLen);
            return out;
        }
    }

    // ---------------------------------------------------------------- internals

    /**
     * {@code T = GHASH(H, AD, C) xor E(K, J0)}, i.e. {@code GHASH xor E(K, IV||0^31||1)} for a 96-bit
     * IV. Written into {@code s.tag}.
     *
     * <p>GCM zero-pads once at the end of the whole AD section and once at the end of the ciphertext,
     * not per component, so both are fed through one streaming state.
     */
    private void authenticate(Scratch s, byte[] iv, byte[][] ad, NativeBuffer ciphertext, int ctLen) {
        NativeBuffer y = s.ghash;
        y.zero(0, BLOCK);
        s.pendingLength = 0;

        if (ad != null) {
            for (byte[] component : ad) {
                for (int i = 0; i < component.length; i++) {
                    hashByte(s, y, component[i]);
                }
            }
        }
        flushPending(s, y);

        for (int i = 0; i < ctLen; i++) {
            hashByte(s, y, ciphertext.get(i));
        }
        flushPending(s, y);

        // Length block: the 64-bit bit-lengths of AD and ciphertext, big-endian.
        s.lengthBlock.zero(0, BLOCK);
        s.lengthBlock.putLong(0, adLength(ad) * 8L);
        s.lengthBlock.putLong(8, ctLen * 8L);
        ghashBlock(s, y, s.lengthBlock, 0);

        // T = Y xor E(K, J0)
        s.counter.zero(0, BLOCK);
        s.counter.copyFrom(iv, 0, 0, IV_BYTES);
        s.counter.put(15, (byte) 1);
        cipher.encryptBlock(s.counter, 0, s.tag, 0);
        s.tag.xorBlock16(0, y, 0);
        y.zero(0, BLOCK);
    }

    /** Appends one byte to the pending GHASH block, folding it in when the block fills. */
    private void hashByte(Scratch s, NativeBuffer y, byte value) {
        s.pending.put(s.pendingLength, value);
        s.pendingLength++;
        if (s.pendingLength == BLOCK) {
            ghashBlock(s, y, s.pending, 0);
            s.pendingLength = 0;
        }
    }

    /** Folds the pending partial block in, zero-padded, per SP 800-38D's single pad per section. */
    private void flushPending(Scratch s, NativeBuffer y) {
        if (s.pendingLength == 0) {
            return;
        }
        for (int i = s.pendingLength; i < BLOCK; i++) {
            s.pending.put(i, (byte) 0);
        }
        ghashBlock(s, y, s.pending, 0);
        s.pendingLength = 0;
    }

    private static int adLength(byte[][] ad) {
        int total = 0;
        if (ad != null) {
            for (byte[] component : ad) {
                total += component.length;
            }
        }
        return total;
    }

    /** {@code y = (y xor block) * H}. */
    private void ghashBlock(Scratch s, NativeBuffer y, NativeBuffer block, int offset) {
        y.xorBlock16(0, block, offset);
        multiplyByH(y);
    }

    /**
     * GF(2^128) multiplication by {@code H}: SP 800-38D algorithm 1.
     *
     * <p>GCM numbers bits with the leftmost bit as bit 0, so the shift direction is the opposite of
     * the RFC 4493 doubling CMAC uses.
     */
    private void multiplyByH(NativeBuffer y) {
        long vh = h.getLong(0);
        long vl = h.getLong(8);
        long xh = y.getLong(0);
        long xl = y.getLong(8);
        long zh = 0;
        long zl = 0;

        for (int i = 0; i < 128; i++) {
            long bit = (i < 64) ? (xh >>> (63 - i)) & 1L : (xl >>> (127 - i)) & 1L;
            if (bit != 0) {
                zh ^= vh;
                zl ^= vl;
            }
            // v = v >> 1, folding the polynomial into the bit that shifts out.
            long lsb = vl & 1L;
            vl = (vl >>> 1) | (vh << 63);
            vh = vh >>> 1;
            if (lsb != 0) {
                vh ^= 0xE100000000000000L;
            }
        }

        y.putLong(0, zh);
        y.putLong(8, zl);
    }

    /** {@code out = AES-CTR(inc32(J0), in)} in place over {@code buf[0..length)}. */
    private void ctr(Scratch s, byte[] iv, NativeBuffer buf, int length) {
        NativeBuffer counter = s.counter;
        counter.zero(0, BLOCK);
        counter.copyFrom(iv, 0, 0, IV_BYTES);
        counter.put(15, (byte) 1);
        incrementCounter(counter);
        for (int offset = 0; offset < length; offset += BLOCK) {
            cipher.encryptBlock(counter, 0, s.keystream, 0);
            buf.xorKeystream(offset, s.keystream, Math.min(BLOCK, length - offset));
            incrementCounter(counter);
        }
        counter.zero(0, BLOCK);
    }

    /** {@code inc32}: increments the rightmost 32 bits modulo 2^32, never the salt. */
    private static void incrementCounter(NativeBuffer counter) {
        for (int i = BLOCK - 1; i >= 12; i--) {
            int b = (counter.get(i) & 0xFF) + 1;
            counter.put(i, (byte) b);
            if (b <= 0xFF) {
                return;
            }
        }
    }

    /** {@code H = E(K, 0^128)}: GHASH's key, and therefore key material. */
    private static NativeBuffer deriveH(AesBlockCipher cipher) {
        NativeBuffer zeros = NativeBuffer.allocate(BLOCK);
        NativeBuffer subkey = NativeBuffer.allocate(BLOCK);
        try {
            cipher.encryptBlock(zeros, 0, subkey, 0);
            return subkey;
        } catch (RuntimeException | Error e) {
            subkey.close();
            throw e;
        } finally {
            zeros.close();
        }
    }

    private void checkUsable() {
        synchronized (lifecycle) {
            if (destroyed) {
                throw new IllegalStateException("key destroyed");
            }
        }
    }

    private static void checkKeyLength(int keyBytes) {
        if (keyBytes != 16 && keyBytes != 24 && keyBytes != 32) {
            throw new IllegalArgumentException("AES-GCM key must be 16, 24 or 32 bytes: " + keyBytes);
        }
    }

    private static void checkIv(byte[] iv) {
        if (iv == null) {
            throw new NullPointerException("iv");
        }
        if (iv.length != IV_BYTES) {
            throw new IllegalArgumentException(
                    "AES-GCM here requires a 96-bit IV: " + iv.length + " bytes");
        }
    }

    @Override
    public void close() {
        synchronized (lifecycle) {
            if (destroyed) {
                return;
            }
            destroyed = true;
        }
        h.close();
        cipher.close();
    }

    @Override
    public String toString() {
        return "GcmKey[" + (destroyed ? "destroyed" : "AES-" + (keyBytes * 8) + "-GCM") + "]";
    }

    /** Per-operation native scratch: 0 = data, 1 = received tag, plus the GHASH state. */
    private final class Scratch implements AutoCloseable {

        private final NativeBuffer[] slots = new NativeBuffer[2];
        private final NativeBuffer keystream;
        private final NativeBuffer tag;
        private final NativeBuffer ghash;
        private final NativeBuffer pending;
        private final NativeBuffer lengthBlock;
        private final NativeBuffer counter;
        private int pendingLength;

        Scratch() {
            keystream = NativeBuffer.allocate(BLOCK);
            tag = NativeBuffer.allocate(BLOCK);
            ghash = NativeBuffer.allocate(BLOCK);
            pending = NativeBuffer.allocate(BLOCK);
            lengthBlock = NativeBuffer.allocate(BLOCK);
            counter = NativeBuffer.allocate(BLOCK);
        }

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
            counter.close();
            lengthBlock.close();
            pending.close();
            ghash.close();
            tag.close();
            keystream.close();
        }
    }
}
