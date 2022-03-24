/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines;


import java.util.Optional;

import javax.crypto.SecretKey;

/**
 * Defines a Data Encapsulation Mechanism (DEM), which is responsible for symmetric encryption and decryption of
 * florentine payloads and for key-wrapping. A Florentine DEM must satisfy the following security properties:
 * <ul>
 *     <li>Deterministic Authenticated Encryption (DAE) as defined in
 *     <a href="https://web.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf">Deterministic Authenticated Encryption: A
 *     Provable-Security Treatment of the Key-Wrap Problem</a> by Rogaway and Shrimpton (2007). Florentines will
 *     always call the DEM with either a unique key value or else with a fresh random value in one of the
 *     associated data elements, ensuring semantic security.</li>
 *     <li>Compactly Committing Authenticated Encryption (ccAEAD) as defined in
 *     <a href="https://eprint.iacr.org/2017/664.pdf">Message Franking via Committing Authenticated Encryption</a>
 *     by Grubbs, Lu, and Ristenpart (2017). This is needed by some {@link KEM} implementations to ensure insider
 *     security.</li>
 * </ul>
 * To distinguish Florentine's DEMs from other DEM constructions that may not have these security properties, we use
 * the term "ccDEM" to refer to Florentine's DEMs where ambiguity would otherwise occur. Generally speaking, these
 * security properties can only be provided by encryption modes that use a collision-resistant hash function for
 * message authentication (such as HMAC).
 */
interface DEM {

    /**
     * A unique identifier for this DEM algorithm.
     */
    String getIdentifier();

    /**
     * Imports raw key material produced by a {@link KEM} or other process and transforms it into a key object
     * suitable for use with this DEM. The key material is assumed to already have been passed through a KDF if
     * necessary to ensure it is suitable as a symmetric key (i.e., indistinguishable from a uniform random string).
     * The input key material should be assumed to have sufficient entropy for cryptographic use and must have at
     * least 256 bits of min-entropy.
     *
     * @param keyMaterial the input key material. The DEM must make a defensive copy of this data, so callers can
     *                    safely wipe the input array after this call returns.
     * @return a key object suitable for use with this DEM.
     */
    DestroyableSecretKey importKey(byte[] keyMaterial);

    /**
     * Begins an encryption process, returning a {@link MessageEncryptor} to specify data to be authenticated and
     * encrypted.
     *
     * @param demKey the key to use for the DEM.
     * @return a message encryptor to continue the encryption process.
     */
    MessageEncryptor beginEncryption(SecretKey demKey);

    /**
     * Begins a decryption process, returning a {@link MessageDecryptor} to specify data to be decrypted and verified.
     *
     * @param demKey the key to use for the DEM.
     * @param siv the synthetic initialisation vector (SIV) or other nonce/tag produced by the encryption process.
     * @return a message decryptor to continue the decryption process.
     */
    MessageDecryptor beginDecryption(SecretKey demKey, byte[] siv);

    /**
     * An object that can be used to authenticate data using a Message Authentication Code (MAC) or similar mechanism.
     * This interface is not intended to be used directly, but instead through one of the two sub-interfaces
     * {@link MessageEncryptor} or {@link MessageDecryptor}.
     *
     * @param <T> the concrete type of authenticator object.
     */
    interface MessageAuthenticator<T extends MessageAuthenticator<T>> {
        /**
         * Processes a packet of data using the underlying Message Authentication Code (MAC) used by the DEM. The
         * data packet is authenticated but not encrypted or decrypted. If this method is called multiple times, then
         * each call is unambiguously distinguished from any other. That is, {@code authenticate(a).authenticate(b)}
         * will produce a distinct authentication code to {@code authenticate(concat(a, b))}.
         *
         * @param data a data packet to include in the authenticated data.
         * @return the same authenticator object to process further packets.
         */
        T authenticate(byte[] data);
    }

    /**
     * An object that can be used to authenticate and encrypt data, providing Deterministic Authenticated Encryption
     * (DAE) or (if one of the components is a random value) Misuse Resistant Authenticated Encryption (MRAE).
     */
    interface MessageEncryptor extends MessageAuthenticator<MessageEncryptor> {
        /**
         * Encrypts and authenticates the given plaintext data. The data will be encrypted in-place. Encryption is
         * only guaranteed to occur after calling {@link #done()}.
         *
         * @param plaintext the plaintext to encrypt and authenticate.
         * @return this encryptor object.
         */
        MessageEncryptor encryptAndAuthenticate(byte[] plaintext);

        /**
         * Indicates that no further message packets require processing and that the encryption process is complete.
         * After completing, all packets passed to {@link #encryptAndAuthenticate(byte[])} are guaranteed to be
         * encrypted (in-place).
         *
         * @return the synthetic IV (SIV) and a caveat key for adding caveats to the Florentine. Only the SIV is
         * required for decryption, so the caveat key can be destroyed and discarded if not needed.
         */
        Pair<byte[], DestroyableSecretKey> done();
    }

    /**
     * An object that can be used to decrypt and verify the authenticity of one or more data packets that were
     * previously encrypted with the corresponding {@link MessageEncryptor}.
     */
    interface MessageDecryptor extends MessageAuthenticator<MessageDecryptor> {
        /**
         * Arranges for the given ciphertext to be decrypted (in-place) and authenticated. Decryption is not guaranteed
         * to occur until a subsequent call to {@link #verify()} has completed.
         *
         * @param ciphertext the ciphertext to decrypt (in-place).
         * @return this object.
         */
        MessageDecryptor decryptAndAuthenticate(byte[] ciphertext);

        /**
         * Verifies that the computed authentication tag matches the SIV that was provided in the call to
         * {@link #beginDecryption(SecretKey, byte[])}. If authentication is successful then all data packets
         * passed to {@link #decryptAndAuthenticate(byte[])} are decrypted and a caveat key is returned that can be
         * used to verify any caveats attached to the Florentine. If authentication fails then all plaintext packets
         * are wiped (to avoid releasing unverified plaintext) and an empty result is returned. No details about the
         * decryption failure reason are provided, to reduce the risk of oracle attacks, but the original cause may
         * be logged. (Note: side-channel oracles may remain, consult the DEM implementation for details).
         *
         * @return the caveat key if authentication succeeds, otherwise an empty result.
         */
        Optional<DestroyableSecretKey> verify();
    }
}
