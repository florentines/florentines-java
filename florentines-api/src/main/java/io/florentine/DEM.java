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

import java.security.MessageDigest;
import java.util.List;
import java.util.Optional;

public final class DEM {
    public static final String A128CTR_HS256 = "A128CTR-HS256";

    static final DEM A128CTR_HS256_DEM = new DEM(A128CTR_HS256, HMAC.HS256, StreamCipher.AES128CTR);

    private final String identifier;
    private final HMAC hmac;
    private final StreamCipher cipher;

    DEM(String identifier, HMAC hmac, StreamCipher cipher) {
        this.identifier = Require.notBlank(identifier, "identifier");
        this.hmac = hmac;
        this.cipher = cipher;
    }

    public String identifier() {
        return identifier;
    }

    DataEncapsulationKey importKey(byte[] keyMaterial, int offset) {
        return new DataEncapsulationKey(keyMaterial, offset,
                hmac.getKeyLenBytes() + cipher.getKeyLenBytes(), identifier);
    }

    public final class Encapsulator implements AutoCloseable {
        private final DataEncapsulationKey key;

        Encapsulator(DataEncapsulationKey key) {
            this.key = key;
        }

        public Encapsulator encapsulate(List<byte[]> publicData, List<byte[]> secretData) {
            assert !key.isDestroyed();
            try (var macKey = hmac.importKey(key.keyMaterial, 0);
                 var encKey = cipher.importKey(key.keyMaterial, hmac.getKeyLenBytes())) {

                var cipherState = cipher.begin(encKey, new byte[16]);
                secretData.forEach(cipherState::encipher);

                var tag = hmac.cascade(macKey, Utils.concat(publicData, secretData));
                key.overwrite(tag);
            }
            return this;
        }

        public byte[] done() {
            try {
                return key.getEncoded();
            } finally {
                key.destroy();
            }
        }

        @Override
        public void close() {
            key.destroy();
        }
    }

    public final class Decapsulator implements AutoCloseable {
        private final DataEncapsulationKey key;
        private final byte[] tag;

        Decapsulator(DataEncapsulationKey key, byte[] tag) {
            this.key = key;
            this.tag = tag.clone();
        }

        public Decapsulator decapsulate(List<byte[]> publicData, List<byte[]> secretData) {
            try (var macKey = hmac.importKey(key.keyMaterial, 0);
                 var encKey = cipher.importKey(key.keyMaterial, hmac.getKeyLenBytes())) {

                var tag = hmac.cascade(macKey, Utils.concat(publicData, secretData));

                var state = cipher.begin(encKey, new byte[16]);
                secretData.forEach(state::decipher);

                key.overwrite(tag);
                return this;
            }
        }

        public Optional<byte[]> done() {
            var valid = MessageDigest.isEqual(tag, key.keyMaterial);
            return !valid || key.isDestroyed() ? Optional.empty() : Optional.of(key.getEncoded());
        }

        @Override
        public void close() {
            done().orElseThrow(() -> new SecurityException("tag validation failed"));
            key.destroy();
        }
    }

    Encapsulator beginEncapsulation(DataEncapsulationKey key) {
        return new Encapsulator(key);
    }

    Decapsulator beginDecapsulation(DataEncapsulationKey key, byte[] tag) {
        return new Decapsulator(key, tag);
    }


    static Optional<DEM> get(String identifier) {
        return switch (identifier) {
            case A128CTR_HS256 -> Optional.of(A128CTR_HS256_DEM);
            default -> Optional.empty();
        };
    }
}
