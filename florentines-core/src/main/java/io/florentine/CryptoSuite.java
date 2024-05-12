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

public abstract class CryptoSuite {
    public static final CryptoSuite X25519_CC20_HS512 = new CryptoSuite() {
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
            return CC20HS512.INSTANCE;
        }
    };

    abstract String identifier();
    abstract AuthKem kem();
    abstract DEM dem();

    private CryptoSuite() {}

    @Override
    public final int hashCode() {
        return identifier().hashCode();
    }

    @Override
    public final boolean equals(Object obj) {
        return obj instanceof CryptoSuite that && this.identifier().equals(that.identifier());
    }

    @Override
    public final String toString() {
        return identifier();
    }
}