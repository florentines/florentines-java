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

import java.security.interfaces.XECPrivateKey;

public final class Algorithm<T,S> {
    private static final AesHmacSivDem DEM = new AesHmacSivDem();

    public static final Algorithm<XECPrivateKey, X25519AuthKemState> X25519_HKDF_A256SIV_HS256 =
            new Algorithm<>(new X25519AuthenticatedKem(DEM), DEM);

    final KEM<T,S> kem;
    final DEM dem;

    private Algorithm(KEM<T,S> kem, DEM dem) {
        this.kem = kem;
        this.dem = dem;
    }

    public String getIdentifier() {
        return "Florentine-" + kem.getIdentifier();
    }

    public S begin(FlorentineSecretKey<T> privateKeys, FlorentinePublicKey... pubklicKeys) {
        return kem.begin(privateKeys, pubklicKeys);
    }
}
