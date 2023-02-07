/*
 * Copyright 2023 Neil Madden.
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

import io.florentine.crypto.KEM;
import io.florentine.crypto.DEM;

import java.security.KeyPair;

public enum AlgorithmSuite {
    AUTHKEM_X25519_A256SIV_HS512(
            "Florentine-AuthKEM-X25519-A256SIV-HS512",
            KEM.X25519_A256SIV_HS512,
            DEM.A256SIV_HS512)
    ;
    final String identifier;
    final KEM kem;
    final DEM dem;

    AlgorithmSuite(String identifier, KEM kem, DEM dem) {
        this.identifier = identifier;
        this.kem = kem;
        this.dem = dem;
    }

    public String getIdentifier() {
        return identifier;
    }

    public KeyPair generateKeyPair() {
        return kem.generateKeyPair();
    }
}
