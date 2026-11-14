package dev.offheap.siv.demo;

import dev.offheap.siv.SecretKeyManager;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import javax.crypto.AEADBadTagException;

/**
 * Field-level encryption for individual database columns, with the key material off-heap.
 *
 * <p>Three key generations, each an {@link Aead}: AES-256-SIV by default, or AES-256-GCM for
 * {@link #createGcm}. Both are supported because the choice is per column, not per system; the
 * difference the caller must know is that only SIV has a deterministic form.
 *
 * <p>Two sealing modes, chosen per column:
 *
 * <ul>
 *   <li><b>Deterministic</b> (no row id): identical values in the same tenant/table/column produce
 *       identical blobs, so the ciphertext itself can carry a UNIQUE constraint or an index and
 *       equality lookups stay server-side. The price is that the database learns which rows share a
 *       value.
 *   <li><b>Bound</b> (row id in the AAD): a fresh nonce per write, so the database learns nothing
 *       about equality, and the blob is authentic only in that one row, that one column, that one
 *       tenant. Relocation is a tag failure rather than a silent substitution.
 * </ul>
 *
 * <p>The stored format is {@code [format][keyVersion][mode][nonce?][ciphertext]}, where the nonce is
 * present (16 bytes, cleartext) only in bound mode. A nonce is not secret, only unique - but it is
 * not part of the SIV output either, so the caller has to keep it somewhere.
 *
 * <p>The version byte is what makes rotation possible: old rows stay readable while new writes use
 * the new key, and a lazy {@link #rewrap} migrates them.
 */
public final class FieldVault implements AutoCloseable {

    /** Bumped only if the byte layout below changes; readers reject anything else. */
    private static final int FORMAT = 1;

    /** format, keyVersion, mode. */
    private static final int HEADER_BYTES = 3;
    private static final byte MODE_DETERMINISTIC = 0;
    private static final byte MODE_BOUND = 1;
    /** SIV mixes any nonce length; GCM here requires exactly 96 bits. */
    private static final int SIV_NONCE_BYTES = 16;
    private static final int GCM_NONCE_BYTES = 12;
    private static final String KEY_PREFIX = "fields-v";
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private final SecretKeyManager keys;
    private final SecureRandom nonces = new SecureRandom();
    private final boolean gcm;
    private final int nonceBytes;
    private volatile int currentVersion;

    private FieldVault(SecretKeyManager keys, int currentVersion, boolean gcm) {
        this.keys = keys;
        this.currentVersion = currentVersion;
        this.gcm = gcm;
        this.nonceBytes = gcm ? GCM_NONCE_BYTES : SIV_NONCE_BYTES;
    }

    /**
     * Creates a vault whose key ring holds {@code versions} generations, all generated from the
     * kernel CSPRNG. A real deployment registers generation 1 and adds generations on rotation; the
     * demo starts with two so rotation is observable without an extra run.
     */
    public static FieldVault create(int versions) throws IOException {
        return create(versions, false);
    }

    /**
     * @param gcm true to back the vault with AES-256-GCM instead of AES-256-SIV
     */
    public static FieldVault create(int versions, boolean gcm) throws IOException {
        SecretKeyManager keys = new SecretKeyManager();
        for (int v = 1; v <= versions; v++) {
            if (gcm) {
                keys.registerGcm(KEY_PREFIX + v);
            } else {
                keys.register(KEY_PREFIX + v, 64);
            }
        }
        return new FieldVault(keys, versions, gcm);
    }

    /** Which cipher backs this vault, for logging and for assertions in tests. */
    public String algorithm() {
        return gcm ? "AES-GCM" : "AES-SIV";
    }

    public int currentVersion() {
        return currentVersion;
    }

    /** Adds a key generation and makes it the write key. Existing blobs stay readable. */
    public synchronized int rotate() throws IOException {
        int next = currentVersion + 1;
        if (gcm) {
            keys.registerGcm(KEY_PREFIX + next);
        } else {
            keys.register(KEY_PREFIX + next, 64);
        }
        currentVersion = next;
        return next;
    }

    /**
     * Retires a generation: its key is zeroed and forgotten, so every blob still carrying that
     * version becomes undecryptable. Refuses the current generation, which would silently break
     * every new write.
     */
    public synchronized boolean removeGeneration(int version) {
        if (version == currentVersion) {
            throw new IllegalArgumentException("cannot remove the current generation " + version);
        }
        return keys.destroy(KEY_PREFIX + version);
    }

    public byte[] seal(String tenant, String table, String column, String rowId, String plaintext) {
        return sealRaw(tenant, table, column, rowId, plaintext.getBytes(UTF8));
    }

    public String open(String tenant, String table, String column, String rowId, byte[] blob)
            throws AEADBadTagException {
        return new String(openRaw(tenant, table, column, rowId, blob), UTF8);
    }

    /** Decrypts under whichever generation sealed it and re-seals under the current one. */
    public byte[] rewrap(String tenant, String table, String column, String rowId, byte[] blob)
            throws AEADBadTagException {
        if (versionOf(blob) == currentVersion) {
            return blob;
        }
        return sealRaw(tenant, table, column, rowId, openRaw(tenant, table, column, rowId, blob));
    }

    public static int versionOf(byte[] blob) {
        if (blob == null || blob.length < HEADER_BYTES) {
            throw new IllegalArgumentException("not a vault blob: too short");
        }
        if (blob[0] != FORMAT) {
            throw new IllegalArgumentException("unsupported vault format " + (blob[0] & 0xFF));
        }
        int version = blob[1] & 0xFF;
        if (version == 0) {
            throw new IllegalArgumentException("invalid key version 0");
        }
        return version;
    }

    private byte[] sealRaw(String tenant, String table, String column, String rowId, byte[] plaintext) {
        byte[][] ad = ad(tenant, table, column, rowId);
        int version = currentVersion;
        String name = KEY_PREFIX + version;
        boolean bound = rowId != null;
        if (!bound && gcm) {
            // Refused here, at the call that would have produced a searchable-looking column, rather
            // than left to the caller to discover that the column cannot be searched.
            throw new UnsupportedOperationException(
                    "AES-GCM has no deterministic form: a GCM vault cannot back an "
                            + "equality-searchable column, pass a row id to bind the value instead");
        }
        byte[] nonce = null;
        byte[] inner;
        if (bound) {
            nonce = new byte[nonceBytes];
            nonces.nextBytes(nonce);
            inner = keys.sealWithNonce(name, nonce, ad, plaintext);
        } else {
            inner = keys.seal(name, ad, plaintext);
        }
        int offset = HEADER_BYTES + (bound ? nonceBytes : 0);
        byte[] out = new byte[offset + inner.length];
        out[0] = (byte) FORMAT;
        out[1] = (byte) version;
        out[2] = bound ? MODE_BOUND : MODE_DETERMINISTIC;
        if (bound) {
            System.arraycopy(nonce, 0, out, HEADER_BYTES, nonceBytes);
        }
        System.arraycopy(inner, 0, out, offset, inner.length);
        return out;
    }

    private byte[] openRaw(String tenant, String table, String column, String rowId, byte[] blob)
            throws AEADBadTagException {
        int version = versionOf(blob);
        byte mode = blob[2];
        boolean bound;
        if (mode == MODE_BOUND) {
            bound = true;
        } else if (mode == MODE_DETERMINISTIC) {
            bound = false;
        } else {
            throw new IllegalArgumentException("unsupported vault mode " + (mode & 0xFF));
        }
        // A bound blob may only be opened as bound: otherwise the mode byte itself would be a
        // downgrade lever, and a deterministic-mode row id check could be skipped.
        if (bound != (rowId != null)) {
            throw new IllegalArgumentException("blob mode does not match the call site");
        }
        int offset = HEADER_BYTES + (bound ? nonceBytes : 0);
        byte[] inner = new byte[blob.length - offset];
        System.arraycopy(blob, offset, inner, 0, inner.length);
        String name = KEY_PREFIX + version;
        byte[][] ad = ad(tenant, table, column, rowId);
        if (bound) {
            byte[] nonce = new byte[nonceBytes];
            System.arraycopy(blob, HEADER_BYTES, nonce, 0, nonceBytes);
            return keys.openWithNonce(name, nonce, ad, inner);
        }
        return keys.open(name, ad, inner);
    }

    /**
     * AAD components are passed as separate S2V components rather than concatenated, so no
     * delimiter can be forged: RFC 5297 mixes each component independently.
     */
    private static byte[][] ad(String tenant, String table, String column, String rowId) {
        byte[] t = tenant.getBytes(UTF8);
        byte[] tb = table.getBytes(UTF8);
        byte[] c = column.getBytes(UTF8);
        if (rowId == null) {
            return new byte[][]{t, tb, c};
        }
        return new byte[][]{t, tb, c, rowId.getBytes(UTF8)};
    }

    @Override
    public void close() {
        keys.close();
    }

    @Override
    public String toString() {
        return "FieldVault[" + (gcm ? "AES-GCM" : "AES-SIV") + ",current=" + currentVersion + ","
                + keys + "]";
    }
}
