package dev.offheap.siv;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Random;

/**
 * JDK 8 self-checking test: RFC 5297 vectors, round-trips, tag rejection, and a differential run
 * against the platform AES (used only as an oracle for the block cipher and CTR).
 *
 * <p>No JUnit on the classpath by design - the point of running this on JDK 8 is to prove the
 * library works there, and FIPS-197/RFC 5297 are the authority, not a test framework.
 */
public final class SivSelfTest {

    private static int checks;
    private static int failures;

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("--dump-key")) {
            dumpKeyForHeapScan(Paths.get(args[1]));
            return;
        }
        rfcVectorA1();
        rfcVectorA2();
        keyLengths();
        tagRejection();
        tamperRejection();
        emptyPlaintext();
        emptyAd();
        manyAd();
        nonceMode();
        handlingOfNonceDiffers();
        keyZeroization();
        ownershipTransfer();
        noNativeLeak();
        concurrentSharing();
        gcmVectors();
        gcmBehaviour();
        gcmConcurrentSharing();
        keyManager();
        System.out.println();
        System.out.println("checks=" + checks + " failures=" + failures);
        if (failures != 0) {
            System.exit(1);
        }
    }

    // ---------------------------------------------------------------- RFC 5297 A.1

    private static void rfcVectorA1() throws Exception {
        byte[] key = hex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] ad = hex("101112131415161718191a1b1c1d1e1f2021222324252627");
        byte[] pt = hex("112233445566778899aabbccddee");
        byte[] wantIv = hex("85632d07c6e8f37f950acd320a2ecc93");
        byte[] wantCt = hex("40c02b9690c4dc04daef7f6afe5c");

        try (SivKey k = SivKey.importKey(key)) {
            byte[] z = k.seal(new byte[][]{ad}, pt);
            check("A.1 IV", wantIv, Arrays.copyOf(z, 16));
            check("A.1 C", wantCt, Arrays.copyOfRange(z, 16, z.length));
            check("A.1 round-trip", pt, k.open(new byte[][]{ad}, z));
        }
    }

    // ---------------------------------------------------------------- RFC 5297 A.2

    private static void rfcVectorA2() throws Exception {
        byte[] key = hex("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
        byte[] ad1 = hex("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100");
        byte[] ad2 = hex("102030405060708090a0");
        byte[] nonce = hex("09f911029d74e35bd84156c5635688c0");
        byte[] pt = hex("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553");
        byte[] wantZ = hex("7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17"
                + "dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d");

        try (SivKey k = SivKey.importKey(key)) {
            byte[] z = k.sealWithNonce(nonce, new byte[][]{ad1, ad2}, pt);
            check("A.2 Z", wantZ, z);
            check("A.2 round-trip", pt, k.openWithNonce(nonce, new byte[][]{ad1, ad2}, z));
        }
    }

    // ---------------------------------------------------------------- key sizes / CTR

    private static void keyLengths() throws Exception {
        for (int keyBytes : new int[]{32, 48, 64}) {
            byte[] key = randomBytes(new Random(7L * keyBytes), keyBytes);
            byte[] pt = randomBytes(new Random(11L * keyBytes), 1 + (keyBytes * 7) % 97);
            byte[] ad = randomBytes(new Random(13L * keyBytes), 5);
            try (SivKey k = SivKey.importKey(key)) {
                check("keyLengths " + keyBytes + "B keyBytes", keyBytes, k.keyBytes());
                byte[] z = k.seal(new byte[][]{ad}, pt);
                check("keyLengths " + keyBytes + "B tag is 16", 16, z.length - pt.length);
                check("keyLengths " + keyBytes + "B round-trip", pt, k.open(new byte[][]{ad}, z));
                // CTR determinism: same key/plaintext/ad must give the same Z.
                check("keyLengths " + keyBytes + "B deterministic", z, k.seal(new byte[][]{ad}, pt));
            }
        }
        check("unsupported key length rejected", true, throwsIae(new byte[31]));
    }

    private static boolean throwsIae(byte[] key) {
        try (SivKey ignored = SivKey.importKey(key)) {
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    // ---------------------------------------------------------------- AEAD behaviour

    private static void tagRejection() throws Exception {
        try (SivKey k = SivKey.generate()) {
            byte[] z = k.seal(new byte[][]{hex("aabb")}, hex("00112233"));
            z[0] ^= 1;
            check("flipped tag rejected", true, throwsBadTag(k, new byte[][]{hex("aabb")}, z));
        }
    }

    private static void tamperRejection() throws Exception {
        try (SivKey k = SivKey.generate()) {
            byte[] z = k.seal(new byte[][]{hex("aabb")}, hex("00112233445566778899aabbccddeeff00"));
            z[z.length - 1] ^= 0x80;
            check("flipped ciphertext rejected", true, throwsBadTag(k, new byte[][]{hex("aabb")}, z));
        }
    }

    private static void handlingOfNonceDiffers() throws Exception {
        try (SivKey k = SivKey.generate()) {
            byte[] pt = hex("deadbeef");
            byte[] withNonce = k.sealWithNonce(hex("00"), null, pt);
            byte[] withoutNonce = k.seal(null, pt);
            check("nonce changes output", false, Arrays.equals(withNonce, withoutNonce));
            check("nonce round-trip", pt, k.openWithNonce(hex("00"), null, withNonce));
            check("nonce required on open", true,
                    throwsBadTag(k, null, withNonce));
        }
    }

    private static boolean throwsBadTag(SivKey k, byte[][] ad, byte[] z) {
        try {
            k.open(ad, z);
            return false;
        } catch (Exception e) {
            return e instanceof javax.crypto.AEADBadTagException;
        }
    }

    private static void emptyPlaintext() throws Exception {
        try (SivKey k = SivKey.generate()) {
            byte[] z = k.seal(new byte[][]{hex("00")}, new byte[0]);
            check("empty plaintext length", 16, z.length);
            check("empty plaintext round-trip", new byte[0], k.open(new byte[][]{hex("00")}, z));
        }
    }

    private static void emptyAd() throws Exception {
        try (SivKey k = SivKey.generate()) {
            byte[] pt = hex("00112233445566778899aabbccddeeff");
            byte[] z1 = k.seal(null, pt);
            byte[] z2 = k.seal(new byte[0][], pt);
            check("null vs empty AD identical", z1, z2);
            check("no-AD round-trip", pt, k.open(null, z1));
        }
    }

    private static void manyAd() throws Exception {
        try (SivKey k = SivKey.generate()) {
            byte[][] ad = new byte[126][];
            for (int i = 0; i < ad.length; i++) {
                ad[i] = new byte[]{(byte) i};
            }
            byte[] pt = hex("ffeedd");
            byte[] z = k.seal(ad, pt);
            check("126 AD components round-trip", pt, k.open(ad, z));
            byte[][] tooMany = new byte[127][];
            for (int i = 0; i < tooMany.length; i++) {
                tooMany[i] = new byte[0];
            }
            boolean rejected = false;
            try {
                k.seal(tooMany, pt);
            } catch (IllegalArgumentException e) {
                rejected = true;
            }
            check("127 AD components rejected", true, rejected);
        }
    }

    private static void nonceMode() throws Exception {
        try (SivKey k = SivKey.generate()) {
            byte[] pt = randomBytes(new Random(3), 100);
            byte[] n1 = hex("0000000000000001");
            byte[] n2 = hex("0000000000000002");
            byte[] z1 = k.sealWithNonce(n1, new byte[][]{hex("aa")}, pt);
            byte[] z2 = k.sealWithNonce(n2, new byte[][]{hex("aa")}, pt);
            check("distinct nonces give distinct output", false, Arrays.equals(z1, z2));
            check("nonce n1 round-trip", pt, k.openWithNonce(n1, new byte[][]{hex("aa")}, z1));
            check("nonce n2 round-trip", pt, k.openWithNonce(n2, new byte[][]{hex("aa")}, z2));
        }
    }

    // ---------------------------------------------------------------- lifecycle

    private static void keyZeroization() throws Exception {
        SivKey k = SivKey.generate();
        k.close();
        k.close();
        boolean threw = false;
        try {
            k.seal(null, new byte[0]);
        } catch (IllegalStateException e) {
            threw = true;
        }
        check("use after close throws", true, threw);
    }

    /**
     * {@code importKey(OffHeapKey)} must take ownership: the handle dies without a second copy of the
     * key existing in native memory.
     */
    private static void ownershipTransfer() throws Exception {
        OffHeapKey handle = OffHeapKey.random(32);
        try (SivKey k = SivKey.importKey(handle)) {
            check("handle dead after transfer", true, destroyed(handle));
            check("transferred key works", 16, k.seal(null, new byte[0]).length);
        }
    }

    private static boolean destroyed(OffHeapKey handle) {
        try {
            handle.length();
            return false;
        } catch (IllegalStateException e) {
            return true;
        }
    }

    /**
     * Native memory is not garbage collected: a region that is allocated and never closed is gone
     * until the process exits. Counting live regions is exact, where watching RSS measures the JIT
     * and the GC as well.
     */
    private static void noNativeLeak() throws Exception {
        long baseline = NativeBuffer.liveRegions();
        for (int i = 0; i < 5000; i++) {
            try (SivKey k = SivKey.generate(i % 2 == 0 ? 32 : 64)) {
                k.sealWithNonce(new byte[]{1, 2, 3}, null, new byte[]{(byte) i});
            }
        }
        long after = NativeBuffer.liveRegions();
        check("5000 keys leave no native region behind (" + baseline + " -> " + after + ")",
                (int) baseline, (int) after);

        // Negative control: an unclosed region must be visible, otherwise the count above proves
        // only that the counter never moves.
        NativeBuffer leaked = NativeBuffer.allocate(32);
        check("accounting notices an unclosed region", (int) (after + 1),
                (int) NativeBuffer.liveRegions());
        leaked.close();
        check("accounting notices the close", (int) after, (int) NativeBuffer.liveRegions());
    }

    /**
     * One {@code SivKey} shared by many threads must produce the same output as a single thread for
     * every message: the per-operation scratch is what makes this pass, and an instance field reused
     * across operations is what would make it fail.
     */
    private static void concurrentSharing() throws Exception {
        final SivKey shared = SivKey.generate();
        try {
            final int n = 400;
            byte[][] expected = new byte[n][];
            for (int i = 0; i < n; i++) {
                expected[i] = shared.seal(new byte[][]{{(byte) i}}, new byte[]{(byte) i, (byte) (i >> 8)});
            }

            final java.util.concurrent.atomic.AtomicInteger mismatches =
                    new java.util.concurrent.atomic.AtomicInteger();
            final java.util.concurrent.atomic.AtomicReference<Throwable> failure =
                    new java.util.concurrent.atomic.AtomicReference<Throwable>();
            Thread[] threads = new Thread[8];
            for (int t = 0; t < threads.length; t++) {
                threads[t] = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            for (int round = 0; round < 4; round++) {
                                for (int i = 0; i < n; i++) {
                                    byte[] z = shared.seal(new byte[][]{{(byte) i}},
                                            new byte[]{(byte) i, (byte) (i >> 8)});
                                    if (!Arrays.equals(z, expected[i])
                                            || !Arrays.equals(shared.open(new byte[][]{{(byte) i}}, z),
                                                    new byte[]{(byte) i, (byte) (i >> 8)})) {
                                        mismatches.incrementAndGet();
                                    }
                                }
                            }
                        } catch (Throwable e) {
                            failure.compareAndSet(null, e);
                        }
                    }
                });
                threads[t].start();
            }
            for (Thread thread : threads) {
                thread.join();
            }
            if (failure.get() != null) {
                throw new AssertionError("concurrent use raised", failure.get());
            }
            check("8 threads share one key without interference", 0, mismatches.get());
        } finally {
            shared.close();
        }
    }

    // ---------------------------------------------------------------- AES-GCM

    /**
     * NIST/McGrew-Viega GCM test cases 13-16: AES-256, including the empty-input case (which is the
     * only one that exercises {@code E(K,J0)} without GHASH) and the AAD cases.
     */
    private static void gcmVectors() throws Exception {
        byte[] k256 = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] iv = hex("cafebabefacedbaddecaf888");
        byte[] pt60 = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        byte[] aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        try (GcmKey k = GcmKey.importKey(new byte[32])) {
            check("GCM TC13 empty/empty", hex("530f8afbc74536b9a963b4f1c4cb738b"),
                    k.seal(new byte[12], null, new byte[0]));
            check("GCM TC14 empty pt, 16 B ct", hex("cea7403d4d606b6e074ec5d3baf39d18"
                            + "d0d1c8a799996bf0265b98b5d48ab919"),
                    k.seal(new byte[12], null, new byte[16]));
        }
        try (GcmKey k = GcmKey.importKey(k256)) {
            check("GCM TC15 60 B pt", hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                            + "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                            + "eb9f796c8d356fc31a8433884b696f4f"),
                    k.seal(iv, null, pt60));
            check("GCM TC16 with 20 B AAD",
                    hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                            + "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                            + "76fc6ece0f4e1768cddf8853bb2d551b"),
                    k.seal(iv, new byte[][]{aad}, pt60));
            check("GCM round-trip", pt60, k.open(iv, new byte[][]{aad},
                    k.seal(iv, new byte[][]{aad}, pt60)));
        }
    }

    private static void gcmBehaviour() throws Exception {
        for (int keyBytes : new int[]{16, 24, 32}) {
            byte[] key = randomBytes(new Random(keyBytes), keyBytes);
            byte[] pt = randomBytes(new Random(keyBytes * 3L), 1 + keyBytes * 2);
            byte[] iv = randomBytes(new Random(keyBytes * 5L), 12);
            try (GcmKey k = GcmKey.importKey(key)) {
                check("GCM " + keyBytes + "B keyBytes", keyBytes, k.keyBytes());
                byte[] z = k.seal(iv, null, pt);
                check("GCM " + keyBytes + "B tag is 16", 16, z.length - pt.length);
                check("GCM " + keyBytes + "B round-trip", pt, k.open(iv, null, z));
            }
        }

        try (GcmKey k = GcmKey.generate()) {
            byte[] iv = hex("000102030405060708090a0b");
            byte[] z = k.seal(iv, null, hex("00112233"));

            byte[] flippedTag = z.clone();
            flippedTag[flippedTag.length - 1] ^= 1;
            check("GCM flipped tag rejected", true, badTag(k, iv, null, flippedTag));

            byte[] flippedCt = z.clone();
            flippedCt[0] ^= 1;
            check("GCM flipped ciphertext rejected", true, badTag(k, iv, null, flippedCt));

            byte[] flippedIv = iv.clone();
            flippedIv[0] ^= 1;
            check("GCM flipped IV rejected", true, badTag(k, flippedIv, null, z));

            check("GCM short input rejected", true, badTag(k, iv, null, new byte[15]));
            check("GCM empty plaintext", 16, k.seal(iv, null, new byte[0]).length);
            check("GCM empty plaintext round-trip", new byte[0], k.open(iv, null,
                    k.seal(iv, null, new byte[0])));

            boolean rejected = false;
            try {
                k.seal(new byte[8], null, new byte[0]);
            } catch (IllegalArgumentException e) {
                rejected = true;
            }
            check("GCM non-96-bit IV rejected", true, rejected);
        }

        GcmKey closed = GcmKey.generate();
        closed.close();
        closed.close();
        check("GCM use after close throws", true, throwsIse(closed));
    }

    private static boolean badTag(GcmKey k, byte[] iv, byte[][] ad, byte[] input) {
        try {
            k.open(iv, ad, input);
            return false;
        } catch (Exception e) {
            return e instanceof javax.crypto.AEADBadTagException;
        }
    }

    private static boolean throwsIse(GcmKey k) {
        try {
            k.seal(new byte[12], null, new byte[0]);
            return false;
        } catch (IllegalStateException e) {
            return true;
        }
    }

    /**
     * The same claim as {@link #concurrentSharing()} for GCM: GHASH state and the counter block are
     * per-operation, otherwise concurrent seals under one key would corrupt each other's tag.
     */
    private static void gcmConcurrentSharing() throws Exception {
        final GcmKey shared = GcmKey.generate();
        try {
            final int n = 400;
            final byte[][] expected = new byte[n][];
            for (int i = 0; i < n; i++) {
                expected[i] = shared.seal(new byte[]{(byte) i, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
                        new byte[][]{{(byte) i}}, new byte[]{(byte) i, (byte) (i >> 8)});
            }

            final java.util.concurrent.atomic.AtomicInteger mismatches =
                    new java.util.concurrent.atomic.AtomicInteger();
            final java.util.concurrent.atomic.AtomicReference<Throwable> failure =
                    new java.util.concurrent.atomic.AtomicReference<Throwable>();
            Thread[] threads = new Thread[8];
            for (int t = 0; t < threads.length; t++) {
                threads[t] = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            for (int round = 0; round < 4; round++) {
                                for (int i = 0; i < n; i++) {
                                    byte[] iv = {(byte) i, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
                                    byte[][] ad = {{(byte) i}};
                                    byte[] pt = {(byte) i, (byte) (i >> 8)};
                                    byte[] z = shared.seal(iv, ad, pt);
                                    if (!Arrays.equals(z, expected[i])
                                            || !Arrays.equals(shared.open(iv, ad, z), pt)) {
                                        mismatches.incrementAndGet();
                                    }
                                }
                            }
                        } catch (Throwable e) {
                            failure.compareAndSet(null, e);
                        }
                    }
                });
                threads[t].start();
            }
            for (Thread thread : threads) {
                thread.join();
            }
            if (failure.get() != null) {
                throw new AssertionError("concurrent GCM use raised", failure.get());
            }
            check("8 threads share one GCM key without interference", 0, mismatches.get());
        } finally {
            shared.close();
        }
    }

    /**
     * The registry has to work for both algorithms without letting the caller confuse them. The
     * dangerous confusion is one-directional: a GCM key in a slot that a searchable column expects
     * would either fail per row or, worse, be adapted into deterministic output that never repeats -
     * so a column would silently stop matching itself. {@code requireDeterministic} turns that into
     * a wiring-time error.
     */
    private static void keyManager() throws Exception {
        byte[] ad = {1, 2, 3};
        byte[] pt = hex("00112233445566778899aabbccddeeff");

        try (SecretKeyManager m = new SecretKeyManager()) {
            m.register("siv", 64);
            m.registerGcm("gcm");

            check("registry holds two keys", 2, m.size());
            check("both names resolve", true, m.has("siv") && m.has("gcm"));

            // Deterministic seal through the registry is stable for SIV...
            check("SIV via registry is deterministic", m.seal("siv", new byte[][]{ad}, pt),
                    m.seal("siv", new byte[][]{ad}, pt));
            check("SIV via registry round-trips", pt,
                    m.open("siv", new byte[][]{ad}, m.seal("siv", new byte[][]{ad}, pt)));

            // ...and unavailable for GCM, which is the whole point of the check below.
            check("GCM rejects a null nonce", 1, rejectsNullNonce(m, ad, pt));

            byte[] iv = new byte[12];
            check("GCM via registry round-trips", pt,
                    m.openWithNonce("gcm", iv, new byte[][]{ad},
                            m.sealWithNonce("gcm", iv, new byte[][]{ad}, pt)));

            check("requireDeterministic accepts SIV", 0, requireDeterministic(m, "siv"));
            check("requireDeterministic rejects GCM", 1, requireDeterministic(m, "gcm"));

            check("destroy reports success", true, m.destroy("gcm"));
            check("destroy is not repeatable", false, m.destroy("gcm"));
            check("one key left", 1, m.size());
        }

        // close() must zero every registered key, including a GCM one, and be idempotent.
        SecretKeyManager m = new SecretKeyManager();
        m.register("siv", 64);
        m.registerGcm("gcm");
        m.close();
        m.close();
        check("closed registry retains nothing", 0, m.size());
    }

    /**
     * 1 when a null nonce is rejected for GCM, 0 when it is wrongly accepted. GCM reports it as an
     * NPE (a null where 12 bytes are mandatory) rather than an IllegalArgumentException; either is a
     * rejection, which is what the contract promises.
     */
    private static int rejectsNullNonce(SecretKeyManager m, byte[] ad, byte[] pt) {
        try {
            m.seal("gcm", new byte[][]{ad}, pt);
            return 0;
        } catch (NullPointerException | IllegalArgumentException expected) {
            return 1;
        }
    }

    private static int requireDeterministic(SecretKeyManager m, String name) {
        try {
            m.requireDeterministic(name);
            return 0;
        } catch (IllegalArgumentException expected) {
            return 1;
        }
    }

    // ---------------------------------------------------------------- heap-scan mode

    /**
     * Holds a live key and seals data, then parks so a heap dump can be taken. The key file is only
     * read off-heap; the plaintext is public test data.
     */
    private static void dumpKeyForHeapScan(Path keyFile) throws Exception {
        SivKey k = SivKey.fromFile(keyFile);
        GcmKey g = GcmKey.fromFile(keyFile);
        byte[] z = k.seal(new byte[][]{hex("feed")}, hex("00112233445566778899aabbccddeeff"));
        byte[] gz = g.seal(hex("000102030405060708090a0b"), null, hex("aabbccdd"));
        System.out.println("READY z=" + toHex(z) + " gcm=" + toHex(gz));
        System.out.flush();
        long deadline = System.currentTimeMillis() + 120_000L;
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(100);
        }
        g.close();
        k.close();
    }

    // ---------------------------------------------------------------- helpers

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    static byte[] randomBytes(Random r, int n) {
        byte[] b = new byte[n];
        r.nextBytes(b);
        return b;
    }

    private static void check(String name, int want, int got) {
        checks++;
        if (want != got) {
            failures++;
            System.out.println("FAIL " + name + ": want " + want + " got " + got);
        } else {
            System.out.println("ok   " + name);
        }
    }

    private static void check(String name, boolean want, boolean got) {
        checks++;
        if (want != got) {
            failures++;
            System.out.println("FAIL " + name + ": want " + want + " got " + got);
        } else {
            System.out.println("ok   " + name);
        }
    }

    private static void check(String name, byte[] want, byte[] got) {
        checks++;
        if (!Arrays.equals(want, got)) {
            failures++;
            System.out.println("FAIL " + name + "\n  want " + toHex(want) + "\n  got  " + toHex(got));
        } else {
            System.out.println("ok   " + name + " " + toHex(got));
        }
    }
}
