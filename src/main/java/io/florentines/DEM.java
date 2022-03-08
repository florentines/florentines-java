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
     * Generates and returns a fresh key suitable for use with this DEM. The returned key should ideally have at
     * least 256 bits of entropy. If the DEM is deterministic then smaller key sizes may result in weaker security
     * than expected in the multi-user setting. If the DEM requires two or more independent keys (e.g., for separate
     * MAC and encryption steps) then it should prefer to derive those keys from a single input key using a KDF
     * rather than generating a larger key here and splitting it in two. The reason for this is explained on page 19
     * of <a href="https://eprint.iacr.org/2017/664.pdf">the paper on ccAEADs.</a>
     * Although this particular security property is not required by Florentines, it may cause surprising failures if
     * the DEM is reused for other applications.
     *
     * @return a fresh DEM key.
     */
    DestroyableSecretKey generateFreshKey();

    /**
     * Imports raw key material produced by a {@link KEM} or other process and transforms it into a key object
     * suitable for use with this DEM. The key material is assumed to already have been passed through a KDF if
     * necessary to ensure it is suitable as a symmetric key (i.e., indistinguishable from a uniform random string).
     * The input key material should be assumed to have sufficient entropy for cryptographic use.
     *
     * @param keyMaterial the input key material.
     * @return a key object suitable for use with this DEM.
     */
    DestroyableSecretKey importKey(byte[] keyMaterial);

    MessageEncryptor beginEncryption(SecretKey demKey);
    MessageDecryptor beginDecryption(SecretKey demKey, byte[] siv);

    interface MessageAuthenticator<T> {
        T authenticate(byte[]... data);
    }

    interface MessageEncryptor extends MessageAuthenticator<MessageEncryptor> {
        MessageEncryptor encryptAndAuthenticate(byte[] plaintext);
        Pair<byte[], DestroyableSecretKey> done();
    }

    interface MessageDecryptor extends MessageAuthenticator<MessageDecryptor> {
        MessageDecryptor decryptAndAuthenticate(byte[] ciphertext);
        Optional<DestroyableSecretKey> verify();
    }
}
