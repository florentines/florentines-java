/*
 * Copyright 2023 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.florentine.crypto;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * A Data Encapsulation Mechanism (DEM). DEMs provide authenticated encryption with associated data (AEAD), but on the
 * relaxed assumption that the encryption key is only used for a single message. All DEMs <strong>MUST</strong> be
 * <em>compactly committing</em>. DEMs <em>SHOULD</em> also provide Deterministic Authenticated Encryption (DAE) in the
 * sense of Rogaway and Shrimpton, in case a protocol error or implementation mistake causes a key to be reused.
 */
public interface DEM {
    /**
     * A DEM implementation based on AES-256 in Synthetic IV (SIV) mode using HMAC-SHA-512 (truncated to 256-bits)
     * for authentication and key derivation.
     */
    DEM A256SIV_HS512 = new A256SIVHS512();

    /**
     * A unique identifier for the algorithm implemented by this DEM. This should either be a registered standard value,
     * or else have a reasonable chance of being unique (such as prefixed with a vendor-specific identifier).
     * Identifiers should be chosen from the ASCII character set regex <code>[a-zA-Z0-9_-]{1,255}</code>.
     *
     * @return the unique identifier of this DEM algorithm,
     */
    String getAlgorithmIdentifier();

    /**
     * Generates a fresh random key for this DEM.
     *
     * @return the DEM key.
     */
    SecretKey generateKey();

    int getTagSizeInBytes();

    /**
     * Imports some key material and converts it into a suitable DEM key. The key material should be assumed to be of
     * high entropy and indistinguishable from a uniformly-random bit-string of at least 256 bits. The caller is
     * responsible for converting any other key material into a suitable format, for example by application of a
     * suitable Key Derivation Function (KDF).
     *
     * @param keyMaterial the key material.
     * @param offset the offset into the key material to use.
     * @param length the length of key material to import.
     * @return the imported key.
     * @throws IllegalArgumentException if the key material is too short or not suitable for this DEM.
     */
    SecretKey importKey(byte[] keyMaterial, int offset, int length);

    /**
     * Imports some key material and converts it into a suitable DEM key. The key material should be assumed to be of
     * high entropy and indistinguishable from a uniformly-random bit-string of at least 256 bits. The caller is
     * responsible for converting any other key material into a suitable format, for example by application of a
     * suitable Key Derivation Function (KDF).
     *
     * @param keyMaterial the key material.
     * @return the imported key.
     * @throws IllegalArgumentException if the key material is too short or not suitable for this DEM.
     */
    default SecretKey importKey(byte[] keyMaterial) {
        return importKey(keyMaterial, 0, keyMaterial.length);
    }


    /**
     * Encrypts the given messages <em>in-place</em> and authenticates them and the given context (associated data).
     * The messages are encrypted as if they formed a single contiguous sequence of bytes. The returned
     * authentication tag <em>commits</em> to the plaintext content of all messages and all context arguments.
     * DEM implementations are required to only be secure if each key is used in a single invocation to one of these
     * encrypt/wrap methods and may lack <em>semantic security</em> if a key is reused. Semantic security can be
     * regained by including a unique random value (nonce) as one of the context arguments: typically the last
     * element. In this case, the DEM provides misuse-resistance authenticated encryption (MRAE).
     *
     * @param key the encryption key.
     * @param messages the messages to encrypt. They will be encrypted in-place and the byte arrays overwritten with
     *                 the encrypted ciphertext. Callers should make a copy of the plaintext if they want to preserve
     *                 it.
     * @param context the context to include as associated data in the authentication (MAC) calculation.
     * @return the authentication tag.
     */
    byte[] encrypt(SecretKey key, Iterable<byte[]> messages, Iterable<byte[]> context);

    /**
     * Convenience method for encrypting a single message with zero or more associated data blocks. Equivalent to
     * calling {@link #encrypt(SecretKey, Iterable, Iterable)} as in the following snippet:
     * <pre>{@code dem.encrypt(key, List.of(message), List.of(context))}</pre>
     *
     * @param key the encryption key.
     * @param message the message to encrypt. It will be encrypted <em>in-place</em> and overwritten with the
     *                encrypted ciphertext.
     * @param context the context to include as associated data in the authentication (MAC) calculation.
     * @return the authentication tag.
     * @see #encrypt(SecretKey, Iterable, Iterable)
     */
    default byte[] encrypt(SecretKey key, byte[] message, byte[]... context) {
        return encrypt(key, List.of(message), List.of(context));
    }

    /**
     * Convenience method when the DEM is being used for key-wrapping. Encrypts the encoded form of a secret key and
     * returns a ciphertext that combines the encrypted data and the authentication tag. The original key is not
     * altered or destroyed by this operation.
     *
     * @param wrapKey the key to use for encrypting another key.
     * @param toEncrypt the key to encrypt (wrap).
     * @param context associated data. This should ideally include the key algorithm and any parameters.
     * @return the encrypted key and authentication tag.
     */
    default byte[] wrap(SecretKey wrapKey, SecretKey toEncrypt, byte[]... context) {
        var encoded = toEncrypt.getEncoded();
        try {
            var tag = encrypt(wrapKey, List.of(encoded), List.of(context));
            return Utils.concat(tag, encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Decrypts...
     * @param key
     * @param messages
     * @param context
     * @param tag
     * @return
     */
    Optional<Iterable<byte[]>> decrypt(SecretKey key, Iterable<byte[]> messages, Iterable<byte[]> context, byte[] tag);

    default Optional<byte[]> decrypt(SecretKey key, byte[] message, byte[] tag, byte[]... context) {
        return decrypt(key, List.of(message), List.of(context), tag)
                .map(it -> it.iterator().next());
    }

    default Optional<SecretKey> unwrap(SecretKey wrapKey, byte[] wrappedKey,
                                       Function<byte[], SecretKey> keyConstructor, byte[]... context) {
        var tag = Arrays.copyOfRange(wrappedKey, 0, getTagSizeInBytes());
        var encoded = Arrays.copyOfRange(wrappedKey, getTagSizeInBytes(), wrappedKey.length);
        try {
            return decrypt(wrapKey, encoded, tag, context)
                    .map(ignore -> keyConstructor.apply(encoded));
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }
}
