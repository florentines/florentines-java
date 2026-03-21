/*
 * Copyright 2026 Neil Madden.
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
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public abstract class DEM {
    public static final String A128SIV_HS256 = "A128SIV-HS256";
    public static final String CC20SIV_HS512 = "CC20SIV-HS512";
    public static final String DEFAULT = A128SIV_HS256;

    private static final Map<String, DEM> registry = new ConcurrentHashMap<>();

    private final String identifier;
    DEM(String identifier) {
        this.identifier = Require.notBlank(identifier, "identifier");
    }

    public String identifier() {
        return identifier;
    }

    DataEncapsulationKey importKey(byte[] keyMaterial, int offset, int length) {
        return new DataEncapsulationKey(keyMaterial, offset, length, identifier);
    }

    abstract KeyAndTag encapsulate(DataEncapsulationKey key,
                                   List<byte[]> publicData,
                                   List<byte[]> secretData);
    abstract Optional<DataEncapsulationKey> decapsulate(DataEncapsulationKey key,
                                                        List<byte[]> publicData,
                                                        List<byte[]> secretData,
                                                        byte[] tag);

    record KeyAndTag(DataEncapsulationKey key, byte[] tag) {}

    static Optional<DEM> get(String identifier) {
        return Optional.ofNullable(registry.get(identifier));
    }

    static void register(DEM dem) {
        if (registry.putIfAbsent(dem.identifier(), dem) != dem) {
            throw new IllegalStateException("DEM identifier already registered");
        }
    }
}
