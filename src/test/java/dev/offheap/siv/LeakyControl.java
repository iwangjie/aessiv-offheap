package dev.offheap.siv;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * The negative control for the heap-dump scan: a deliberately leaky AES-SIV usage, written the way
 * most Java code does it - key bytes retained in a heap array. The scanner must find the key here,
 * which proves the scanner is capable of finding keys at all.
 *
 * <p>Not part of the library. Test-only, and only ever run to validate the verification harness.
 */
public final class LeakyControl {

    /** Heap-resident key, kept reachable so it survives GC and shows up in a live heap dump. */
    static byte[] retainedKey;

    public static void main(String[] args) throws Exception {
        retainedKey = Files.readAllBytes(Paths.get(args[0]));
        byte[] copy = retainedKey.clone();
        boolean match = copy.length > 0;
        System.out.println("READY leaky len=" + retainedKey.length + " copied=" + match);
        System.out.flush();
        long deadline = System.currentTimeMillis() + 120_000L;
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(100);
        }
    }

    private LeakyControl() {
    }
}
