/*
 * Copyright 2025-2026 Neil Madden.
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

package io.florentine.dem;

import io.florentine.crypto.DestroyableSecretKey;

import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

public abstract class DEM {
    public static final String CC20SIV_HS512 = "CC20SIV-HS512";
    public static final String CC20SIV_B3512 = "CC20SIV-B3512";
    public static final String A128SIV_HS256 = "A128SIV-HS256";

    private final String identifier;

    DEM(String identifier) {
        this.identifier = requireNonNull(identifier);
    }

    public static Optional<DEM> get(String identifier) {
        return switch (identifier) {
            case CC20SIV_HS512 -> Optional.of(CC20SIVHS512.INSTANCE);
            case CC20SIV_B3512 -> Optional.of(CC20SIVB3512.INSTANCE);
            case A128SIV_HS256 -> Optional.of(A128SIVHS256.INSTANCE);
            default -> Optional.empty();
        };
    }

    public static DEM getDefault() {
        return CC20SIVB3512.INSTANCE;
    }

    public final String identifier() {
        return identifier;
    }

    public DestroyableSecretKey importKey(byte[] keyMaterial) {
        return new DestroyableSecretKey(keyMaterial, identifier);
    }

    public abstract KeyAndTag encapsulate(DestroyableSecretKey key, List<byte[]> publicData, List<byte[]> secretData);
    public abstract Optional<DestroyableSecretKey> decapsulate(
            DestroyableSecretKey key, List<byte[]> publicData, List<byte[]> secretData, byte[] tag);

    public record KeyAndTag(DestroyableSecretKey key, byte[] tag) {}
}
