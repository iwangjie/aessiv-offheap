package dev.offheap.siv;

import javax.crypto.AEADBadTagException;

/**
 * An authenticated cipher whose key material lives off the heap.
 *
 * <p>The two implementations differ in one way that matters far beyond the API: AES-SIV has a
 * deterministic form, so equal plaintexts under the same key and AD produce equal output - which is
 * what makes server-side equality search possible, and is also the leak that comes with it. AES-GCM
 * has no such form: it needs a fresh 96-bit nonce on every call, and repeating one is a break, not a
 * leak of equality.
 *
 * <p>Keys are {@link AutoCloseable} because closing zeroes the round keys; a caller that forgets
 * leaves key material in native memory until the process exits.
 */
public interface Aead extends AutoCloseable {

    /**
     * The nonce length this algorithm insists on, or 0 when a null nonce is also accepted.
     *
     * <p>0 means the algorithm has a deterministic form: AES-SIV accepts null (deterministic) or a
     * nonce of any length (the RFC 5297 nonce variant). A non-zero value means exactly that many
     * bytes are required and null is rejected, as with AES-GCM's 96-bit IV. The distinction is what
     * {@link SecretKeyManager#requireDeterministic(String)} tests, because only a 0 can back an
     * equality-searchable column.
     */
    int nonceBytes();

    /**
     * @param nonce null only when {@link #nonceBytes()} is 0; exactly that many bytes otherwise
     * @return the authenticated ciphertext, tag included
     */
    byte[] seal(byte[] nonce, byte[][] ad, byte[] plaintext);

    /** @throws AEADBadTagException when the tag does not hold; nothing is returned in that case */
    byte[] open(byte[] nonce, byte[][] ad, byte[] ciphertextAndTag) throws AEADBadTagException;

    @Override
    void close();
}
