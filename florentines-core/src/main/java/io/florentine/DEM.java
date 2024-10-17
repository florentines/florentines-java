/*
 * Copyright 2024 Neil Madden.
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

package io.florentine;

import java.util.List;
import java.util.Optional;

import javax.crypto.SecretKey;

/**
 * A Data Encapsulation Mechanism (DEM). This is essentially a symmetric authenticated encryption with associated data
 * (AEAD) implementation, with the requirement that the key is unique for each call to
 * {@link #encapsulate(SecretKey, Iterable)}. Florentines also requires that the DEM is <em>compactly
 * committing</em>. That is, that the authentication tag is a cryptographic commitment to the plaintext of all records
 * in the message. This implies that the MAC involved is at least second preimage-resistant to an attacker that knows
 * the key.
 */
public abstract class DEM {

    public abstract String identifier();

    abstract DestroyableSecretKey generateKey();

    /**
     * Encrypts and authenticates the given records. Each record can have some secret content, which is encrypted, and
     * some public content, which is authenticated but not encrypted. Each record may also have some associated data,
     * which is also authenticated.
     *
     * @param key the encryption key.
     * @param records the records to encapsulate.
     * @return the authentication tag.
     */
    abstract byte[] encapsulate(SecretKey key, Iterable<? extends Record> records);

    /**
     * Decrypts and verifies the given records.
     *
     * @param key the decryption key.
     * @param records the records to verify and decrypt.
     * @param tag the authentication tag.
     * @return the computed tag, if verification succeeds, or else an empty result.
     */
    abstract Optional<byte[]> decapsulate(SecretKey key, Iterable<? extends Record> records, byte[] tag);

    static abstract class Record {
        abstract List<byte[]> secretContent();
        abstract List<byte[]> publicContent();
    }
}
