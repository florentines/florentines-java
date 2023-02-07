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

import io.florentine.Utils;

import javax.crypto.SecretKey;
import java.util.Arrays;
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

    int sivSizeBytes();

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

    Encryptor beginEncrypt(SecretKey key);
    Decryptor beginDecrypt(SecretKey key);

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
        try (var cipher = beginEncrypt(wrapKey)) {
            var siv = cipher.authenticate(context).authenticate(encoded).encrypt(encoded);
            return Utils.concat(siv, encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    default Optional<SecretKey> unwrap(SecretKey wrapKey, byte[] wrappedKey,
                                       Function<byte[], SecretKey> keyConstructor, byte[]... context) {
        var siv = Arrays.copyOfRange(wrappedKey, 0, sivSizeBytes());
        var encoded = Arrays.copyOfRange(wrappedKey, sivSizeBytes(), wrappedKey.length);
        try (var cipher = beginDecrypt(wrapKey)) {
            return cipher.authenticate(context).authenticate(encoded).decrypt(siv, encoded)
                    .map(ignore -> keyConstructor.apply(encoded));
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    interface Encryptor extends AutoCloseable {
        Encryptor authenticate(byte[]... chunks);
        byte[] encrypt(byte[]... chunks);
        byte[] done();
        default void close() {
            done();
        }
    }

    interface Decryptor extends AutoCloseable {
        Decryptor authenticate(byte[]... chunks);
        Optional<byte[]> decrypt(byte[] siv, byte[]... chunks);
        void close();
    }
}
