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

package io.florentine.crypto;

public interface CryptoSuite {
    CryptoSuite X25519_CC20_HS512 = new CryptoSuite() {
        @Override
        public String identifier() {
            return "X25510-CC20-HS512";
        }

        @Override
        public AuthKem kem() {
            return new X25519AuthKem(this);
        }

        @Override
        public DEM dem() {
            return DEM.CC20HS512;
        }
    };

    String identifier();
    AuthKem kem();
    DEM dem();
}

//String identifier, AuthKem kem, HashFunction hash, StreamCipher cipher) {
//}
