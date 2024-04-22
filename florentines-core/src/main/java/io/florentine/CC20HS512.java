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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.crypto.SecretKey;

enum CC20HS512 implements DEM {
    INSTANCE;

    private static final byte[] HKDF_SUBKEY_CONTEXT = "Florentine-DEM-CC20-HS512-SubKeys".getBytes(UTF_8);
    private static final byte[] ZERO_NONCE = new byte[12];

    private final StreamCipher cipher = StreamCipher.CC20;
    private final PRF prf = HashFunction.SHA512.asPRF(64);

    @Override
    public DestroyableSecretKey importKey(byte[] keyMaterial) {
        return HKDF.expandToKey(
                new DestroyableSecretKey(keyMaterial, prf.algorithm()),
                HKDF_SUBKEY_CONTEXT,
                64,
                identifier());
    }

    @Override
    public CaveatKeyAndTag encrypt(SecretKey key, List<? extends Part> parts) {
        var keyTag = validateKey(key);
        for (var part : parts) {
            keyTag = encryptPart(keyTag, part);
        }

        var tag = Arrays.copyOfRange(keyTag, 48, 64);
        var caveatKey = new DestroyableSecretKey(keyTag, identifier());

        return new CaveatKeyAndTag(caveatKey, tag);
    }

    private byte[] encryptPart(byte[] keyMaterial, Part part) {
        assert keyMaterial.length == 64;

        try (var macKey = new DestroyableSecretKey(keyMaterial,  0, 32, prf.algorithm());
             var encKey = new DestroyableSecretKey(keyMaterial, 32, 64, cipher.algorithm())) {
            if (part.isEncrypted()) {
                // Key is unique for each record, so can use a simple 0 nonce.
                cipher.cipher(encKey, ZERO_NONCE, part.content());
            }
            return prf.apply(macKey, part.header(), part.content());
        }
    }

    private byte[] validateKey(SecretKey key) {
        var keyBytes = key.getEncoded();
        if (!identifier().equals(key.getAlgorithm()) || keyBytes == null || keyBytes.length != 64) {
            throw new IllegalArgumentException("invalid key");
        }
        return keyBytes;
    }

    @Override
    public Optional<DestroyableSecretKey> decrypt(SecretKey key, List<? extends Part> parts, byte[] expectedTag) {
        if (expectedTag.length != 16) {
            return Optional.empty();
        }

        var keyTag = validateKey(key);
        for (var part : parts) {
            keyTag = decryptPart(keyTag, part);
        }

        // Tag is last 16 bytes
        var computedTag = Arrays.copyOfRange(keyTag, 48, 64);
        if (!MessageDigest.isEqual(computedTag, expectedTag)) {
            CryptoUtils.wipe(computedTag);
            for (var part : parts) {
                CryptoUtils.wipe(part.content());
            }
            return Optional.empty();
        }

        var caveatKey = new DestroyableSecretKey(Arrays.copyOf(keyTag, 32), "HmacSHA512");
        CryptoUtils.wipe(computedTag, keyTag);
        return Optional.of(caveatKey);
    }

    @Override
    public PRF prf() {
        return prf;
    }

    @Override
    public StreamCipher cipher() {
        return cipher;
    }

    private byte[] decryptPart(byte[] keyMaterial, Part part) {
        assert keyMaterial.length == 64;

        try (var macKey = new DestroyableSecretKey(keyMaterial,  0, 32, prf.algorithm());
             var encKey = new DestroyableSecretKey(keyMaterial, 32, 64, cipher.algorithm())) {
            var tag = prf.apply(macKey, part.header(), part.content());
            if (part.isEncrypted()) {
                // Key is unique for each record, so can use a simple 0 nonce.
                cipher.cipher(encKey, ZERO_NONCE, part.content());
            }
            return tag;
        }
    }
}
