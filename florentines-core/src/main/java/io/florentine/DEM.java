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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

/**
 * A Data Encapsulation Mechanism (DEM). A DEM provides authenticated encryption of Florentine records under the
 * assumption that a given key is only ever used to encrypt a single message.
 */
abstract class DEM {
    /**
     * The default DEM algorithm if no "dem" field is present in the header.
     */
    public static final String DEFAULT_ALGORITHM = "CC20-HS512";
    private static final Map<String, DEM> registry = new ConcurrentHashMap<>();

    DEM() {
        // Package-private constructor
    }

    /**
     * Registers a DEM algorithm in the registry of algorithms supported by this library.
     *
     * @param impl the dem to register.
     * @return the DEM instance registered. Note that this may not be the same as the instance passed as an argument
     * if this DEM has already been registered.
     */
    static DEM register(DEM impl) {
        var existing = registry.putIfAbsent(impl.identifier(), impl);
        return existing != null ? existing : impl;
    }

    /**
     * Looks up a DEM by identifier.
     *
     * @param identifier the DEM identifier.
     * @return the DEM implementation or empty if it is unknown.
     */
    static Optional<DEM> lookup(String identifier) {
        return Optional.ofNullable(registry.get(identifier));
    }

    /**
     * An identifer for this DEM.
     *
     * @return the DEM identifier.
     */
    abstract String identifier();

    /**
     * The size of the key used by this DEM, in bytes.
     *
     * @return the key size in bytes.
     */
    abstract int keySizeBytes();

    /**
     * Imports some key material to be used for this DEM. The key material must be uniformly random and at least 256
     * bits in length. It will be wiped as a side-effect of calling this method.
     *
     * @param keyMaterial the input key material.
     * @return the imported DEM key.
     */
    abstract DataKey importKey(byte[] keyMaterial);

    /**
     * Encapsulates one or more data records. Record contents and their associated headers will be authenticated and
     * any encrypted records will be encrypted in-place. A new DEM key will be returned that can be used to
     * encapsulate any further records, such as caveats.
     *
     * @param key the DEM key.
     * @param records the records to encapsulate.
     * @return a new DEM key that both authenticates the given records and can be used to process further records.
     */
    abstract DataKey encapsulate(SecretKey key, List<Florentine.Record> records);

    /**
     * Attempts to authenticate and decrypt the given records. If this process succeeds then a new DEM key is
     * returned that can be used to process further records, such as caveats. Otherwise an empty result is returned
     * and no details are provided as to why decryption failed, to prevent oracle attacks.
     *
     * @param key the DEM key.
     * @param records the records to decapsulate.
     * @param expectedTag the expected tag to use to verify the records, which should be obtained by calling
     * {@link #tag(DataKey)} on the result of a call to {@link #encapsulate(SecretKey, List)}.
     * @return the caveat key or an empty result if authentication fails.
     */
    abstract Optional<DataKey> decapsulate(SecretKey key, List<Florentine.Record> records,
                                           byte[] expectedTag);

    /**
     * Converts a DEM key returned from {@link #encapsulate(SecretKey, List)} into a short tag that can be used as an
     * argument to {@link #decapsulate(SecretKey, List, byte[])} to verify authenticity of records processed. The
     * returned tag must be exactly 16 bytes long, and must not reveal any information about the key.
     *
     * @param key the key.
     * @return the tag derived from the key.
     */
    public byte[] tag(DataKey key) {
        return HKDF.expand(key, "Florentine-Tag".getBytes(UTF_8), 16);
    }

    abstract KeyWrapper asKeyWrapper();
}
