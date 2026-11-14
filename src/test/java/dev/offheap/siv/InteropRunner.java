package dev.offheap.siv;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Reads hex cases produced by {@code tools/interop.py} and writes our output for each, so the Python
 * reference implementations (pycryptodome's {@code AES.MODE_SIV} and {@code AES.MODE_GCM}) can
 * compare byte for byte.
 *
 * <p>Line format, tab separated: {@code algorithm, key, iv-or-"-", ad-count, ad..., plaintext}, where
 * {@code algorithm} is {@code siv} or {@code gcm}. Empty fields are the empty string, so an absent AD
 * set is count 0 and an empty plaintext is "".
 */
public final class InteropRunner {

    public static void main(String[] args) throws Exception {
        Path in = Paths.get(args[0]);
        Path out = Paths.get(args[1]);
        try (BufferedReader r = Files.newBufferedReader(in, StandardCharsets.UTF_8);
             BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.isEmpty()) {
                    continue;
                }
                w.write(runCase(line.split("\t", -1)));
                w.newLine();
            }
        }
    }

    private static String runCase(String[] f) {
        String algorithm = f[0];
        byte[] key = hex(f[1]);
        byte[] nonce = f[2].equals("-") ? null : hex(f[2]);
        int adCount = Integer.parseInt(f[3]);
        byte[][] ad = new byte[adCount][];
        for (int i = 0; i < adCount; i++) {
            ad[i] = hex(f[4 + i]);
        }
        byte[] plaintext = hex(f[4 + adCount]);
        if (algorithm.equals("gcm")) {
            return runGcm(key, nonce, ad, plaintext);
        }
        return runSiv(key, nonce, ad, plaintext);
    }

    private static String runGcm(byte[] key, byte[] iv, byte[][] ad, byte[] plaintext) {
        try (GcmKey k = GcmKey.importKey(key)) {
            byte[] z = k.seal(iv, ad, plaintext);
            byte[] back = k.open(iv, ad, z);
            if (!java.util.Arrays.equals(back, plaintext)) {
                throw new IllegalStateException("GCM round-trip failed");
            }
            return toHex(z);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String runSiv(byte[] key, byte[] nonce, byte[][] ad, byte[] plaintext) {
        try (SivKey k = SivKey.importKey(key)) {
            byte[] z = nonce == null
                    ? k.seal(ad, plaintext)
                    : k.sealWithNonce(nonce, ad, plaintext);
            byte[] back = nonce == null ? k.open(ad, z) : k.openWithNonce(nonce, ad, z);
            if (!java.util.Arrays.equals(back, plaintext)) {
                throw new IllegalStateException("AES-SIV round-trip failed");
            }
            return toHex(z);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    private InteropRunner() {
    }
}
