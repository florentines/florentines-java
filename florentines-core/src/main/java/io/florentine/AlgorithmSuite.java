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

import io.florentine.crypto.AnonKEM;
import io.florentine.crypto.AuthKEM;
import io.florentine.crypto.DEM;

public enum AlgorithmSuite {
    AUTHKEM_X25519_A256SIV_HS512(
            "Florentine-AuthKEM-X25519-A256SIV-HS512",
            AuthKEM.X25519_A256SIV_HS512,
            DEM.A256SIV_HS512)
    ;
    final String identifier;
    final AuthKEM authKem;
    final AnonKEM anonKem;
    final DEM dem;

    AlgorithmSuite(String identifier, AuthKEM kem, DEM dem) {
        this.identifier = identifier;
        this.authKem = kem;
        this.anonKem = null;
        this.dem = dem;
    }

    AlgorithmSuite(String identifier, AnonKEM kem, DEM dem) {
        this.identifier = identifier;
        this.authKem = null;
        this.anonKem = kem;
        this.dem = dem;
    }

    public boolean isAuthenticated() {
        return authKem != null;
    }
}
