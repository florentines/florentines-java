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
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.US_ASCII;

public final class DEM {
    public static final String A128SIV_HS256 = "A128SIV-HS256";
    public static final String CC20SIV_HS512 = "CC20SIV-HS512";

    static final DEM A128SIV_HS256_DEM = new DEM(A128SIV_HS256, HMAC.HS256, StreamCipher.AES128CTR);
    static final DEM CC20SIV_HS512_DEM = new DEM(CC20SIV_HS512, HMAC.HS512, StreamCipher.CHACHA20);
    public static final int SIV_LENGTH = 16;

    private final String identifier;
    private final HMAC hmac;
    private final StreamCipher cipher;
    private final byte[] kdfSalt;

    DEM(String identifier, HMAC hmac, StreamCipher cipher) {
        this.identifier = Require.notBlank(identifier, "identifier");
        this.hmac = hmac;
        this.cipher = cipher;
        this.kdfSalt = ("Florentine-DEM-" + identifier + "-KDF-Salt").getBytes(US_ASCII);
    }

    public String identifier() {
        return identifier;
    }

    DataEncapsulationKey importKey(byte[] keyMaterial, int offset) {
        return new DataEncapsulationKey(keyMaterial, offset, hmac.getKeyLenBytes(), identifier);
    }

    public final class Encapsulator implements AutoCloseable {
        private final DataEncapsulationKey key;

        Encapsulator(DataEncapsulationKey key) {
            this.key = key;
        }

        public byte[] encapsulate(List<byte[]> publicData, List<byte[]> secretData) {
            try (var macKey = hmac.importKey(key.keyMaterial, 0);
                 var encKey = cipher.importKey(hmac.extractIndependentKey(kdfSalt, key.keyMaterial), 0)) {

                var tag = computeTag(macKey, publicData, secretData);
                var siv = Arrays.copyOfRange(tag, tag.length - SIV_LENGTH, tag.length);
                var state = cipher.begin(encKey, siv);
                secretData.forEach(state::encipher);
                key.overwrite(tag);
                return siv;
            }
        }

        public DataEncapsulationKey done() {
            try {
                return key.copy();
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

        Decapsulator(DataEncapsulationKey key) {
            this.key = key;
        }

        public Optional<Decapsulator> decapsulate(List<byte[]> publicData, List<byte[]> secretData, byte[] siv) {
            if (siv.length != SIV_LENGTH) {
                return Optional.empty();
            }

            try (var macKey = hmac.importKey(key.keyMaterial, 0);
                 var encKey = cipher.importKey(hmac.extractIndependentKey(kdfSalt, key.keyMaterial), 0)) {

                var state = cipher.begin(encKey, siv);
                secretData.forEach(state::decipher);

                var computedTag = computeTag(macKey, publicData, secretData);
                var computedSiv = Arrays.copyOfRange(computedTag, computedTag.length - SIV_LENGTH, computedTag.length);
                if (!MessageDigest.isEqual(computedSiv, siv)) {
                    secretData.forEach(Crypto::wipe);
                    key.destroy();
                    return Optional.empty();
                }

                key.overwrite(computedTag);
                return Optional.of(this);
            }
        }

        public Optional<DataEncapsulationKey> done() {
            return key.isDestroyed() ? Optional.empty() : Optional.of(key.copy());
        }

        @Override
        public void close() {
            key.destroy();
        }
    }

    Encapsulator beginEncapsulation(DataEncapsulationKey key) {
        return new Encapsulator(key);
    }

    Decapsulator beginDecapsulation(DataEncapsulationKey key) {
        return new Decapsulator(key);
    }

    private byte[] computeTag(HMAC.HmacKey macKey, List<byte[]> publicData, List<byte[]> secretData) {
        try (var subKey = hmac.importKey(hmac.cascade(macKey, publicData), 0)) {
            return hmac.cascade(subKey, secretData);
        }
    }

    static Optional<DEM> get(String identifier) {
        return switch (identifier) {
            case A128SIV_HS256 -> Optional.of(A128SIV_HS256_DEM);
            case CC20SIV_HS512 -> Optional.of(CC20SIV_HS512_DEM);
            default -> Optional.empty();
        };
    }
}
