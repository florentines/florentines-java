/*
 * Copyright 2022 Neil Madden.
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

package software.pando.florentines;

import java.util.Optional;
import java.util.function.Consumer;

import javax.crypto.SecretKey;

/**
 * A data encapsulation mechanism (DEM) for Florentines. A DEM is essentially an authenticated encryption with
 * associated data (AEAD) mode, except that we guarantee that each DEM key is only used once. This allows purely
 * deterministic implementations to be used. Florentine DEMs are required to be compactly committing: the
 * authentication tag/SIV must commit to the key and the plaintext. That is, an attacker that knows the key should be
 * unable to find another key/associated data/plaintext combination that produces the same tag.
 */
interface DEM {
    /**
     * A DEM implementation based on XSalsa20 in a Synthetic IV mode using HMAC-SHA-512-256 as the PRF.
     */
    DEM XS20SIV_HS512 = new XS20SIVHS512();

    /**
     * The standard algorithm identifier for this DEM.
     *
     * @return the standard algorithm identifier.
     */
    String getIdentifier();

    /**
     * Factory method to construct a key for this DEM from the given key material. The key material is assumed to be
     * uniformly random and to contain at least 256 bits of entropy.
     *
     * @param keyMaterial the key material.
     * @return a key object for this DEM.
     */
    SecretKey key(byte[] keyMaterial);

    /**
     * Authenticates the given blocks of data and returns a cipher state object that contains a <em>chaining key</em>
     * that authenticates the given data, and a stream cipher for encrypting a subset of the data blocks.
     *
     * @param key the key to use for authentication and encryption.
     * @param data the blocks of data to authenticate. Blocks are processed unambiguously so that ["aa", "b"] and
     *             ["a", "ab"] always produce distinct tags.
     * @return the cipher state.
     */
    CipherState authenticate(SecretKey key, byte[]... data);

    /**
     * Decrypts the given ciphertext blocks using the given key and SIV.
     *
     * @param key the key to use for decryption and verification.
     * @param siv the synthetic iv produced during encryption.
     * @param ciphertexts the payloads to decrypt.
     * @return a verifier to use to check the authenticity of the data.
     */
    Verifier decrypt(SecretKey key, byte[] siv, byte[]... ciphertexts);

    abstract class CipherState {
        final SecretKey chainKey;
        CipherState(SecretKey chainKey) {
            this.chainKey = chainKey;
        }

        SecretKey done() {
            return chainKey;
        }

        CipherState chainingKey(Consumer<SecretKey> consumer) {
            consumer.accept(chainKey);
            return this;
        }

        abstract byte[] andEncrypt(byte[]... payloads);
    }

    interface Verifier {
        /**
         * Verifies the authenticity of the given blocks of data.
         *
         * @param blocks the blocks to authenticate
         * @return if verification is successful, then returns the chaining key, otherwise an empty result.
         */
        Optional<SecretKey> andVerify(byte[]... blocks);
    }
}
