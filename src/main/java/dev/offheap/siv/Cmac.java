package dev.offheap.siv;

/**
 * CMAC (RFC 4493) over AES.
 *
 * <p>The subkeys {@code K1}/{@code K2} are as sensitive as the key (they are {@code E(K,0)} doubled),
 * so they are computed once per key and kept in native memory by {@link KeyMaterial}; every {@code
 * Cmac} instance borrows them read-only. Only the chaining value and the pending block are
 * per-instance mutable state, and {@link #close()} zeroes them.
 *
 * <p>The pending block is only encrypted when more input arrives, so the caller controls which bytes
 * end up in the final block - which is the entire point of CMAC's last-block rule.
 */
final class Cmac implements AutoCloseable {

    private static final int BLOCK = 16;

    private final AesBlockCipher cipher;
    private final NativeBuffer subkeys;
    private final NativeBuffer chain;
    private final NativeBuffer block;
    private int blockLength;

    /**
     * @param subkeys {@code K1 || K2}, 32 bytes, owned by the caller and outliving this instance
     */
    Cmac(AesBlockCipher cipher, NativeBuffer subkeys) {
        if (subkeys.size() < 2 * BLOCK) {
            throw new IllegalArgumentException("subkey region must be 32 bytes");
        }
        this.cipher = cipher;
        this.subkeys = subkeys;
        this.chain = NativeBuffer.allocate(BLOCK);
        this.block = NativeBuffer.allocate(BLOCK);
    }

    void reset() {
        chain.zero(0, BLOCK);
        block.zero(0, BLOCK);
        blockLength = 0;
    }

    /** Feeds {@code count} zero bytes without materialising them (S2V's {@code <zero>} input). */
    void updateZeros(int count) {
        for (int i = 0; i < count; i++) {
            if (blockLength == BLOCK) {
                absorb();
            }
            block.put(blockLength, (byte) 0);
            blockLength++;
        }
    }

    void update(byte[] src, int offset, int length) {
        int end = offset + length;
        int i = offset;
        while (i < end) {
            if (blockLength == BLOCK) {
                absorb();
            }
            int n = Math.min(BLOCK - blockLength, end - i);
            block.copyFrom(src, i, blockLength, n);
            blockLength += n;
            i += n;
        }
    }

    void update(NativeBuffer src, int offset, int length) {
        int i = 0;
        while (i < length) {
            if (blockLength == BLOCK) {
                absorb();
            }
            int n = Math.min(BLOCK - blockLength, length - i);
            block.copyFrom(src, offset + i, blockLength, n);
            blockLength += n;
            i += n;
        }
    }

    /** Completes CMAC and writes the 16-byte tag to {@code out[outOffset..outOffset+16)}. */
    void finishInto(NativeBuffer out, int outOffset) {
        if (blockLength == BLOCK) {
            block.xorBlock16(0, subkeys, 0);
        } else {
            block.put(blockLength, (byte) 0x80);
            for (int i = blockLength + 1; i < BLOCK; i++) {
                block.put(i, (byte) 0);
            }
            block.xorBlock16(0, subkeys, BLOCK);
        }
        absorb();
        out.copyFrom(chain, 0, outOffset, BLOCK);
    }

    private void absorb() {
        chain.xorBlock16(0, block, 0);
        cipher.encryptBlock(chain, 0, chain, 0);
        block.zero(0, BLOCK);
        blockLength = 0;
    }

    /** {@code v = v * x} in GF(2^128) with the RFC 4493 polynomial {@code x^128+x^7+x^2+x+1}. */
    static void dblInPlace(NativeBuffer v, int offset) {
        int high = v.get(offset) & 0x80;
        int carry = 0;
        for (int i = BLOCK - 1; i >= 0; i--) {
            int b = v.get(offset + i) & 0xFF;
            v.put(offset + i, (byte) ((b << 1) | carry));
            carry = b >>> 7;
        }
        if (high != 0) {
            v.put(offset + BLOCK - 1, (byte) (v.get(offset + BLOCK - 1) ^ 0x87));
        }
    }

    @Override
    public void close() {
        chain.close();
        block.close();
    }
}
