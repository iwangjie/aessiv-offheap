package dev.offheap.siv;

/**
 * A byte region in native memory, zeroed on allocation and on {@link #close()}.
 *
 * <p>Every secret this package touches - raw key, AES round keys, CMAC subkeys, the AES state
 * during key expansion, the working copy of the plaintext - lives in one of these. Nothing here has
 * a heap-backed alternative, so a heap dump or a {@code byte[]} scan cannot observe it.
 *
 * <p>Accesses are bounds-checked against {@link #size()} except for the explicit
 * {@code *Unchecked} variants, which exist for the AES round loop where every offset is a fixed
 * multiple of 4 inside a region allocated for exactly that many words.
 */
final class NativeBuffer implements AutoCloseable {

    /**
     * Live-region accounting. Native memory is invisible to the GC, so a region that is allocated and
     * never closed is lost until the process exits; this counter makes that observable instead of
     * something you discover as a slowly growing RSS.
     */
    private static final boolean LITTLE_ENDIAN =
            java.nio.ByteOrder.nativeOrder() == java.nio.ByteOrder.LITTLE_ENDIAN;

    private static long liveRegions;

    private long address;
    private final int size;

    private NativeBuffer(long address, int size) {
        this.address = address;
        this.size = size;
    }

    static NativeBuffer allocate(int size) {
        if (size <= 0) {
            throw new IllegalArgumentException("size must be positive: " + size);
        }
        long address = UnsafeAccess.U.allocateMemory(size);
        UnsafeAccess.U.setMemory(address, size, (byte) 0);
        liveRegions++;
        return new NativeBuffer(address, size);
    }

    int size() {
        return size;
    }

    private void check(int offset, int length) {
        if (offset < 0 || length < 0 || offset > size - length) {
            throw new IndexOutOfBoundsException(
                    "offset=" + offset + " length=" + length + " size=" + size);
        }
    }

    byte get(int offset) {
        check(offset, 1);
        return UnsafeAccess.U.getByte(address + offset);
    }

    void put(int offset, byte value) {
        check(offset, 1);
        UnsafeAccess.U.putByte(address + offset, value);
    }

    /** Native-order int read: only for values that are stored and read by this class alone. */
    int getIntRaw(int offset) {
        check(offset, 4);
        return UnsafeAccess.U.getInt(address + offset);
    }

    /**
     * Big-endian int read, matching how AES and CTR define their 32-bit words.
     *
     * <p>One native read plus a byte swap; the byte-at-a-time version was four bounds-checked
     * {@code Unsafe} calls per word and dominated the block cipher's cost.
     */
    int getInt(int offset) {
        check(offset, 4);
        int raw = UnsafeAccess.U.getInt(address + offset);
        return LITTLE_ENDIAN ? Integer.reverseBytes(raw) : raw;
    }

    void putInt(int offset, int value) {
        check(offset, 4);
        UnsafeAccess.U.putInt(address + offset, LITTLE_ENDIAN ? Integer.reverseBytes(value) : value);
    }

    /** Big-endian 64-bit read; GHASH and GCM's length block are defined on 64-bit words. */
    long getLong(int offset) {
        check(offset, 8);
        long raw = UnsafeAccess.U.getLong(address + offset);
        return LITTLE_ENDIAN ? Long.reverseBytes(raw) : raw;
    }

    void putLong(int offset, long value) {
        check(offset, 8);
        UnsafeAccess.U.putLong(address + offset, LITTLE_ENDIAN ? Long.reverseBytes(value) : value);
    }

    /**
     * Same as {@link #getInt} without the bounds check.
     *
     * <p>Only for callers whose offsets come from their own loop bounds (the AES round keys and the
     * AES state are both fixed-size and indexed by the round count). The check is ~40% of the block
     * cipher's instruction count and the invariant is local, so it is asserted once at construction
     * instead of once per word.
     */
    int getIntUnchecked(int offset) {
        int raw = UnsafeAccess.U.getInt(address + offset);
        return LITTLE_ENDIAN ? Integer.reverseBytes(raw) : raw;
    }

    void putIntUnchecked(int offset, int value) {
        UnsafeAccess.U.putInt(address + offset, LITTLE_ENDIAN ? Integer.reverseBytes(value) : value);
    }

    void zero(int offset, int length) {
        check(offset, length);
        UnsafeAccess.U.setMemory(address + offset, length, (byte) 0);
    }

    void copyFrom(NativeBuffer src, int srcOffset, int dstOffset, int length) {
        src.check(srcOffset, length);
        check(dstOffset, length);
        UnsafeAccess.U.copyMemory(src.address + srcOffset, address + dstOffset, length);
    }

    void copyFrom(byte[] src, int srcOffset, int dstOffset, int length) {
        if (srcOffset < 0 || length < 0 || srcOffset > src.length - length) {
            throw new IndexOutOfBoundsException("src array too short for " + length + " bytes");
        }
        check(dstOffset, length);
        UnsafeAccess.U.copyMemory(src, UnsafeAccess.BYTE_BASE + srcOffset, null,
                address + dstOffset, length);
    }

    /**
     * Copies {@code length} bytes starting at absolute index {@code srcOffset} of {@code src}.
     *
     * <p>Absolute indexing matters: a sequential-fill loop has already advanced the buffer's position
     * past the bytes it just read, and mutating the position back would race with the channel.
     */
    void copyFrom(java.nio.ByteBuffer src, int srcOffset, int dstOffset, int length) {
        if (srcOffset < 0 || length < 0 || srcOffset > src.limit() - length) {
            throw new IndexOutOfBoundsException(
                    "srcOffset=" + srcOffset + " length=" + length + " limit=" + src.limit());
        }
        check(dstOffset, length);
        for (int i = 0; i < length; i++) {
            UnsafeAccess.U.putByte(address + dstOffset + i, src.get(srcOffset + i));
        }
    }

    void copyTo(byte[] dst, int dstOffset, int srcOffset, int length) {
        if (dstOffset < 0 || length < 0 || dstOffset > dst.length - length) {
            throw new IndexOutOfBoundsException("dst array too short for " + length + " bytes");
        }
        check(srcOffset, length);
        UnsafeAccess.U.copyMemory(null, address + srcOffset, dst,
                UnsafeAccess.BYTE_BASE + dstOffset, length);
    }

    /**
     * {@code this[dstOffset..dstOffset+16) ^= src[srcOffset..srcOffset+16)} using native-order ints.
     *
     * <p>Byte order is irrelevant when both operands go through the same reinterpretation, and 4
     * native reads replace 32 bounds-checked byte accesses on the CTR and CMAC hot paths.
     */
    void xorBlock16(int dstOffset, NativeBuffer src, int srcOffset) {
        src.check(srcOffset, 16);
        check(dstOffset, 16);
        UnsafeAccess.U.putInt(address + dstOffset,
                UnsafeAccess.U.getInt(address + dstOffset) ^ src.getIntRaw(srcOffset));
        UnsafeAccess.U.putInt(address + dstOffset + 4,
                UnsafeAccess.U.getInt(address + dstOffset + 4) ^ src.getIntRaw(srcOffset + 4));
        UnsafeAccess.U.putInt(address + dstOffset + 8,
                UnsafeAccess.U.getInt(address + dstOffset + 8) ^ src.getIntRaw(srcOffset + 8));
        UnsafeAccess.U.putInt(address + dstOffset + 12,
                UnsafeAccess.U.getInt(address + dstOffset + 12) ^ src.getIntRaw(srcOffset + 12));
    }

    /**
     * {@code this[dstOffset..dstOffset+length) ^= src[srcOffset..)} of keystream, 16 bytes at a time
     * with a byte tail, so a whole-block XOR costs four int operations instead of 32 byte ones.
     */
    void xorKeystream(int dstOffset, NativeBuffer keystream, int length) {
        check(dstOffset, length);
        int i = 0;
        for (; i + 16 <= length; i += 16) {
            xorBlock16(dstOffset + i, keystream, i);
        }
        for (; i < length; i++) {
            put(dstOffset + i, (byte) (get(dstOffset + i) ^ keystream.get(i)));
        }
    }

    /** Compares two 16-byte tags without early exit, so timing reveals only equality. */
    boolean equalsConstantTime(NativeBuffer other) {
        if (other.size() < size) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < size; i++) {
            diff |= get(i) ^ other.get(i);
        }
        return diff == 0;
    }

    /** Regions still allocated process-wide; 0 after every key is closed. */
    static long liveRegions() {
        return liveRegions;
    }

    @Override
    public void close() {
        if (address != 0) {
            UnsafeAccess.U.setMemory(address, size, (byte) 0);
            UnsafeAccess.U.freeMemory(address);
            address = 0;
            liveRegions--;
        }
    }

    @Override
    public String toString() {
        return "NativeBuffer[size=" + size + (address == 0 ? ",freed" : "") + "]";
    }
}
