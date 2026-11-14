package dev.offheap.siv;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.AEADBadTagException;

/**
 * Named registry of authenticated ciphers, none of whose keys has a heap representation.
 *
 * <p>The manager owns every key it registers: {@link #destroy(String)} and {@link #close()} zero the
 * round keys in native memory. Key names are heap Strings, but a name is an identifier, not key
 * material.
 *
 * <p>Keys are looked up per operation rather than cached, so {@code destroy} takes effect
 * immediately and a callback cannot hold a live key past the call.
 *
 * <p>Both {@link SivKey} and {@link GcmKey} can be registered. The nonce-handling methods dispatch
 * on the registered algorithm rather than adapting one to the other: an AES-SIV key in a {@code Gcm}
 * slot would silently produce deterministic output where the caller expects a fresh nonce, so
 * {@link #requireDeterministic(String)} exists to make the mismatch a registration-time error.
 */
public final class SecretKeyManager implements AutoCloseable {

    private final Map<String, Aead> keys = new HashMap<String, Aead>();
    private boolean closed;

    /** AES-128-SIV key from the kernel CSPRNG, matching {@link SivKey#generate()}. */
    public SecretKeyManager register(String name) throws IOException {
        return register(name, SivKey.generate());
    }

    public SecretKeyManager register(String name, int keyBytes) throws IOException {
        return register(name, SivKey.generate(keyBytes));
    }

    /** AES-256-GCM key from the kernel CSPRNG. */
    public SecretKeyManager registerGcm(String name) throws IOException {
        return register(name, GcmKey.generate());
    }

    /**
     * Imports the key file into native memory. The file must stay readable by the process; the bytes
     * are read once by {@link OffHeapKey#fromFile} and never touch the heap.
     */
    public SecretKeyManager registerFromFile(String name, Path keyFile) throws IOException {
        return register(name, SivKey.fromFile(keyFile));
    }

    public SecretKeyManager registerFromFileGcm(String name, Path keyFile) throws IOException {
        return register(name, GcmKey.fromFile(keyFile));
    }

    /** Takes ownership of {@code key}: the manager closes it on destroy/close. */
    public SecretKeyManager register(String name, Aead key) {
        checkOpen();
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name must not be empty");
        }
        if (key == null) {
            throw new NullPointerException("key");
        }
        Aead previous = keys.put(name, key);
        if (previous != null) {
            // Re-registration replaces the old key and must not leave it live.
            previous.close();
        }
        return this;
    }

    /**
     * Asserts that the named key has a deterministic form, so an equality-searchable column cannot be
     * silently backed by a key that needs a nonce. Called at registration/wiring time, not per row.
     *
     * @return this, for chaining
     */
    public SecretKeyManager requireDeterministic(String name) {
        Aead key = key(name);
        if (key.nonceBytes() != 0) {
            throw new IllegalArgumentException(
                    name + " is an " + key + " key: it has no deterministic form and cannot back an "
                            + "equality-searchable column");
        }
        return this;
    }

    public boolean has(String name) {
        return keys.containsKey(name);
    }

    public byte[] seal(String name, byte[][] ad, byte[] plaintext) {
        return key(name).seal(null, ad, plaintext);
    }

    public byte[] sealWithNonce(String name, byte[] nonce, byte[][] ad, byte[] plaintext) {
        return key(name).seal(nonce, ad, plaintext);
    }

    public byte[] open(String name, byte[][] ad, byte[] ivAndCiphertext)
            throws AEADBadTagException {
        return key(name).open(null, ad, ivAndCiphertext);
    }

    public byte[] openWithNonce(String name, byte[] nonce, byte[][] ad, byte[] ivAndCiphertext)
            throws AEADBadTagException {
        return key(name).open(nonce, ad, ivAndCiphertext);
    }

    /** Zeroes and forgets one key. Returns whether it existed. */
    public boolean destroy(String name) {
        Aead key = keys.remove(name);
        if (key == null) {
            return false;
        }
        key.close();
        return true;
    }

    public int size() {
        return keys.size();
    }

    private Aead key(String name) {
        checkOpen();
        Aead key = keys.get(name);
        if (key == null) {
            throw new IllegalArgumentException("no key registered under that name");
        }
        return key;
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("manager closed");
        }
    }

    /** Zeroes every key. Idempotent. */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        List<Aead> all = new ArrayList<Aead>(keys.values());
        keys.clear();
        for (Aead key : all) {
            key.close();
        }
    }

    @Override
    public String toString() {
        return "SecretKeyManager[" + keys.size() + " keys" + (closed ? ",closed" : "") + "]";
    }
}
