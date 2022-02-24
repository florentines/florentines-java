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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.interfaces.XECPrivateKey;

public final class Algorithm<T> {

    public static final Algorithm<XECPrivateKey> X25519_A256SIV_HS256 = new Algorithm<>(
            new X25519AuthenticatedKem(new AesHmacSivDem(),
                    "Florentine-AuthKEM-X25519-HKDF-A256SIV-HS256".getBytes(UTF_8)), new AesHmacSivDem());

    final KEM<T> kem;
    final DEM dem;

    private Algorithm(KEM<T> kem, DEM dem) {
        this.kem = kem;
        this.dem = dem;
    }

    public String getIdentifier() {
        return "Florentine-" + kem.getIdentifier();
    }
}
