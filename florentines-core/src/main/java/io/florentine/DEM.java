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
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

abstract class DEM {
    public static final String DEFAULT_ALGORITHM = "CC20-HS512";
    private static final Map<String, DEM> registry = new ConcurrentHashMap<>();

    DEM() {
        // Package-private constructor
    }

    static DEM register(DEM impl) {
        var existing = registry.putIfAbsent(impl.identifier(), impl);
        return existing != null ? existing : impl;
    }

    static Optional<DEM> lookup(String identifier) {
        return Optional.ofNullable(registry.get(identifier));
    }

    public String identifier() {
        return cipher().identifier() + "-" + prf().identifier();
    }

    abstract DestroyableSecretKey importKey(byte[] keyMaterial);
    abstract CaveatKeyAndTag encrypt(SecretKey key, List<Florentine.Record> parts);
    abstract Optional<DestroyableSecretKey> decrypt(SecretKey key, List<Florentine.Record> parts, byte[] expectedTag);

    abstract PRF prf();
    abstract StreamCipher cipher();

    KeyWrapCipher asKeyWrapCipher() {
        return new SyntheticIVMode(identifier().replaceAll("(CTR)?-", "SIV-"), cipher(), prf());
    }

    record CaveatKeyAndTag(DestroyableSecretKey caveatKey, byte[] tag) {}
}
