package dev.offheap.siv;

/**
 * AES-128/192/256 single-block encryption with the expanded key schedule held in native memory.
 *
 * <p>The key schedule is the most valuable secret an AES implementation touches - it is the raw key
 * spread over {@code 16*(Nr+1)} bytes and survives for the lifetime of the cipher. It lives in a
 * {@link NativeBuffer} and is zeroed by {@link #close()}. The AES state itself is kept in four
 * {@code int} locals: it is derived from the message being encrypted, never from the key alone, and
 * registers/stack frames are not part of the Java heap.
 *
 * <p>Table-based AES (the classic T-tables) would leak key material through cache timing; this uses
 * the byte-oriented S-box plus an arithmetic MixColumns, so the only data-dependent memory access is
 * a 256-byte table lookup on the *state*, which is the standard software tradeoff (constant-time
 * bitsliced AES is out of scope here and documented in the README).
 */
final class AesBlockCipher implements AutoCloseable {

    private static final int BLOCK = 16;

    private final NativeBuffer roundKeys;
    private final int rounds;

    /** Expands {@code keyBytes} bytes of key at {@code keyOffset} into the round-key buffer. */
    AesBlockCipher(NativeBuffer key, int keyOffset, int keyBytes) {
        if (keyBytes != 16 && keyBytes != 24 && keyBytes != 32) {
            throw new IllegalArgumentException("AES key must be 16/24/32 bytes: " + keyBytes);
        }
        int nk = keyBytes / 4;
        this.rounds = nk + 6;
        int words = 4 * (rounds + 1);
        this.roundKeys = NativeBuffer.allocate(words * 4);
        try {
            expandKeySchedule(key, keyOffset, nk, words);
        } catch (RuntimeException e) {
            roundKeys.close();
            throw e;
        }
    }

    private void expandKeySchedule(NativeBuffer key, int keyOffset, int nk, int words) {
        for (int i = 0; i < nk; i++) {
            roundKeys.putIntUnchecked(i * 4, key.getIntUnchecked(keyOffset + i * 4));
        }
        int rcon = 1;
        for (int i = nk; i < words; i++) {
            int temp = roundKeys.getIntUnchecked((i - 1) * 4);
            if (i % nk == 0) {
                temp = subWord(Integer.rotateLeft(temp, 8)) ^ (rcon << 24);
                rcon = xtime(rcon);
            } else if (nk > 6 && i % nk == 4) {
                temp = subWord(temp);
            }
            roundKeys.putIntUnchecked(i * 4, roundKeys.getIntUnchecked((i - nk) * 4) ^ temp);
        }
    }

    /**
     * {@code out = AES(in)} for one 16-byte block; {@code src} and {@code dst} may not overlap.
     *
     * <p>All native access below is unchecked: the round-key region is exactly
     * {@code 16 * (rounds + 1)} bytes and every offset is derived from the round counter or from a
     * caller-visible block start that {@link #checkOffsets} has already validated.
     */
    void encryptBlock(NativeBuffer src, int srcOffset, NativeBuffer dst, int dstOffset) {
        if (srcOffset < 0 || dstOffset < 0
                || srcOffset > src.size() - BLOCK || dstOffset > dst.size() - BLOCK) {
            throw new IndexOutOfBoundsException(
                    "block out of range: src=" + srcOffset + "/" + src.size()
                            + " dst=" + dstOffset + "/" + dst.size());
        }
        int s0 = src.getIntUnchecked(srcOffset) ^ roundKeys.getIntUnchecked(0);
        int s1 = src.getIntUnchecked(srcOffset + 4) ^ roundKeys.getIntUnchecked(4);
        int s2 = src.getIntUnchecked(srcOffset + 8) ^ roundKeys.getIntUnchecked(8);
        int s3 = src.getIntUnchecked(srcOffset + 12) ^ roundKeys.getIntUnchecked(12);

        int rk = 16;
        for (int round = 1; round < rounds; round++) {
            int t0 = (sb(s0, 0) << 24) | (sb(s1, 1) << 16) | (sb(s2, 2) << 8) | sb(s3, 3);
            int t1 = (sb(s1, 0) << 24) | (sb(s2, 1) << 16) | (sb(s3, 2) << 8) | sb(s0, 3);
            int t2 = (sb(s2, 0) << 24) | (sb(s3, 1) << 16) | (sb(s0, 2) << 8) | sb(s1, 3);
            int t3 = (sb(s3, 0) << 24) | (sb(s0, 1) << 16) | (sb(s1, 2) << 8) | sb(s2, 3);
            s0 = mix(t0) ^ roundKeys.getIntUnchecked(rk);
            s1 = mix(t1) ^ roundKeys.getIntUnchecked(rk + 4);
            s2 = mix(t2) ^ roundKeys.getIntUnchecked(rk + 8);
            s3 = mix(t3) ^ roundKeys.getIntUnchecked(rk + 12);
            rk += 16;
        }

        int t0 = (sb(s0, 0) << 24) | (sb(s1, 1) << 16) | (sb(s2, 2) << 8) | sb(s3, 3);
        int t1 = (sb(s1, 0) << 24) | (sb(s2, 1) << 16) | (sb(s3, 2) << 8) | sb(s0, 3);
        int t2 = (sb(s2, 0) << 24) | (sb(s3, 1) << 16) | (sb(s0, 2) << 8) | sb(s1, 3);
        int t3 = (sb(s3, 0) << 24) | (sb(s0, 1) << 16) | (sb(s1, 2) << 8) | sb(s2, 3);
        dst.putIntUnchecked(dstOffset, t0 ^ roundKeys.getIntUnchecked(rk));
        dst.putIntUnchecked(dstOffset + 4, t1 ^ roundKeys.getIntUnchecked(rk + 4));
        dst.putIntUnchecked(dstOffset + 8, t2 ^ roundKeys.getIntUnchecked(rk + 8));
        dst.putIntUnchecked(dstOffset + 12, t3 ^ roundKeys.getIntUnchecked(rk + 12));
    }

    /** S-box of the byte at {@code row} (0 = most significant) of one column word. */
    private static int sb(int word, int row) {
        return SBOX[(word >>> (24 - 8 * row)) & 0xFF] & 0xFF;
    }

    private static int subWord(int w) {
        return ((SBOX[(w >>> 24) & 0xFF] & 0xFF) << 24)
                | ((SBOX[(w >>> 16) & 0xFF] & 0xFF) << 16)
                | ((SBOX[(w >>> 8) & 0xFF] & 0xFF) << 8)
                | (SBOX[w & 0xFF] & 0xFF);
    }

    private static int mix(int w) {
        int a = (w >>> 24) & 0xFF;
        int b = (w >>> 16) & 0xFF;
        int c = (w >>> 8) & 0xFF;
        int d = w & 0xFF;
        // 3x == 2x ^ x, so each output byte is the column itself xored with the doubled terms.
        int a2 = xtime(a);
        int b2 = xtime(b);
        int c2 = xtime(c);
        int d2 = xtime(d);
        return ((a2 ^ b2 ^ b ^ c ^ d) << 24)
                | ((a ^ b2 ^ c2 ^ c ^ d) << 16)
                | ((a ^ b ^ c2 ^ d2 ^ d) << 8)
                | (a2 ^ a ^ b ^ c ^ d2);
    }

    private static int xtime(int x) {
        return ((x << 1) ^ ((x >>> 7) * 0x1B)) & 0xFF;
    }

    @Override
    public void close() {
        roundKeys.close();
    }

    private static final byte[] SBOX = {
        0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5,
        (byte) 0x30, 0x01, 0x67, 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, 0x76,
        (byte) 0xca, (byte) 0x82, (byte) 0xc9, 0x7d, (byte) 0xfa, 0x59, 0x47, (byte) 0xf0,
        (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, 0x72, (byte) 0xc0,
        (byte) 0xb7, (byte) 0xfd, (byte) 0x93, 0x26, 0x36, 0x3f, (byte) 0xf7, (byte) 0xcc,
        0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, 0x71, (byte) 0xd8, 0x31, 0x15,
        0x04, (byte) 0xc7, 0x23, (byte) 0xc3, 0x18, (byte) 0x96, 0x05, (byte) 0x9a,
        0x07, 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, 0x27, (byte) 0xb2, 0x75,
        0x09, (byte) 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, (byte) 0xa0,
        0x52, 0x3b, (byte) 0xd6, (byte) 0xb3, 0x29, (byte) 0xe3, 0x2f, (byte) 0x84,
        0x53, (byte) 0xd1, 0x00, (byte) 0xed, 0x20, (byte) 0xfc, (byte) 0xb1, 0x5b,
        0x6a, (byte) 0xcb, (byte) 0xbe, 0x39, 0x4a, 0x4c, 0x58, (byte) 0xcf,
        (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, 0x43, 0x4d, 0x33, (byte) 0x85,
        0x45, (byte) 0xf9, 0x02, 0x7f, 0x50, 0x3c, (byte) 0x9f, (byte) 0xa8,
        0x51, (byte) 0xa3, 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, 0x38, (byte) 0xf5,
        (byte) 0xbc, (byte) 0xb6, (byte) 0xda, 0x21, 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2,
        (byte) 0xcd, 0x0c, 0x13, (byte) 0xec, 0x5f, (byte) 0x97, 0x44, 0x17,
        (byte) 0xc4, (byte) 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, (byte) 0x81, 0x4f, (byte) 0xdc, 0x22, 0x2a, (byte) 0x90, (byte) 0x88,
        0x46, (byte) 0xee, (byte) 0xb8, 0x14, (byte) 0xde, 0x5e, 0x0b, (byte) 0xdb,
        (byte) 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        (byte) 0xc2, (byte) 0xd3, (byte) 0xac, 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, 0x79,
        (byte) 0xe7, (byte) 0xc8, 0x37, 0x6d, (byte) 0x8d, (byte) 0xd5, 0x4e, (byte) 0xa9,
        0x6c, 0x56, (byte) 0xf4, (byte) 0xea, 0x65, 0x7a, (byte) 0xae, 0x08,
        (byte) 0xba, 0x78, 0x25, 0x2e, 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6,
        (byte) 0xe8, (byte) 0xdd, 0x74, 0x1f, 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a,
        0x70, 0x3e, (byte) 0xb5, 0x66, 0x48, 0x03, (byte) 0xf6, 0x0e,
        0x61, 0x35, 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, 0x1d, (byte) 0x9e,
        (byte) 0xe1, (byte) 0xf8, (byte) 0x98, 0x11, 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94,
        (byte) 0x9b, 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, 0x55, 0x28, (byte) 0xdf,
        (byte) 0x8c, (byte) 0xa1, (byte) 0x89, 0x0d, (byte) 0xbf, (byte) 0xe6, 0x42, 0x68,
        0x41, (byte) 0x99, 0x2d, 0x0f, (byte) 0xb0, 0x54, (byte) 0xbb, 0x16,
    };
}
