package dev.offheap.siv;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * Key bytes held only in native memory.
 *
 * <p>There is deliberately no constructor and no accessor that yields a {@code byte[]}: the material
 * can be produced from the kernel CSPRNG or a file, consumed by {@link SivAead}, and destroyed - it
 * never has to cross the heap. {@link #close()} zeroes the region before freeing it.
 */
public final class OffHeapKey implements AutoCloseable {

    private static final String URANDOM = "/dev/urandom";
    private static final int MAX_LENGTH = 64;

    private NativeBuffer buffer;

    private OffHeapKey(NativeBuffer buffer) {
        this.buffer = buffer;
    }

    /**
     * Random key from {@code /dev/urandom}. The bytes go kernel buffer -> direct buffer -> native
     * memory; the staging direct buffer is off-heap, so no key byte is ever reachable from a heap
     * dump.
     */
    public static OffHeapKey random(int length) throws IOException {
        try (FileChannel ch = FileChannel.open(Paths.get(URANDOM), StandardOpenOption.READ)) {
            return read(ch, length);
        }
    }

    /** Reads exactly {@code length} bytes from {@code src} straight into native memory. */
    public static OffHeapKey read(ReadableByteChannel src, int length) throws IOException {
        checkLength(length);
        NativeBuffer buffer = NativeBuffer.allocate(length);
        try {
            ByteBuffer stage = ByteBuffer.allocateDirect(Math.min(length, 64));
            int written = 0;
            while (written < length) {
                stage.clear();
                stage.limit(Math.min(stage.capacity(), length - written));
                int n = src.read(stage);
                if (n < 0) {
                    throw new IOException(
                            "key source ended after " + written + " of " + length + " bytes");
                }
                buffer.copyFrom(stage, 0, written, n);
                written += n;
            }
            stage.clear();
            return new OffHeapKey(buffer);
        } catch (IOException | RuntimeException e) {
            buffer.close();
            throw e;
        }
    }

    public static OffHeapKey fromFile(Path file) throws IOException {
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            long size = ch.size();
            if (size > MAX_LENGTH) {
                throw new IOException("key file longer than " + MAX_LENGTH + " bytes: " + size);
            }
            return read(ch, (int) size);
        }
    }

    /**
     * Imports key material that already exists on the heap. This is the only entry point that
     * accepts {@code byte[]}, and the caller is responsible for the copy it handed over - the JVM
     * gives us no way to wipe it.
     */
    public static OffHeapKey importFrom(byte[] key) {
        checkLength(key.length);
        NativeBuffer buffer = NativeBuffer.allocate(key.length);
        buffer.copyFrom(key, 0, 0, key.length);
        return new OffHeapKey(buffer);
    }

    /**
     * Any AES key size this package can use: 16 bytes for AES-128 (GCM), 24 for AES-192 (GCM only),
     * 32 for AES-256 (both), 48/64 for AES-192/256-SIV's split key.
     */
    private static void checkLength(int length) {
        if (length < 16 || length > MAX_LENGTH) {
            throw new IllegalArgumentException("key must be 16.." + MAX_LENGTH + " bytes: " + length);
        }
    }

    public int length() {
        return live().size();
    }

    NativeBuffer buffer() {
        return live();
    }

    private NativeBuffer live() {
        if (buffer == null) {
            throw new IllegalStateException("key already destroyed");
        }
        return buffer;
    }

    /**
     * Hands the region over to the caller and marks this handle dead: the buffer is not copied and
     * not freed, so ownership moves without a second copy of the key existing.
     */
    NativeBuffer transfer() {
        NativeBuffer moved = live();
        buffer = null;
        return moved;
    }

    /** Zeroes and frees the key. Idempotent. */
    public void destroy() {
        if (buffer != null) {
            buffer.close();
            buffer = null;
        }
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public String toString() {
        return "OffHeapKey[" + (buffer == null ? "destroyed" : buffer.size() + "B native") + "]";
    }
}
