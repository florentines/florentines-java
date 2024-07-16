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

import static io.florentine.HashFunction.SHA512;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

import java.security.MessageDigest;
import java.util.List;
import java.util.Optional;

import javax.crypto.SecretKey;

final class EncryptThenPRF extends DEM {
    public static final DEM CC20_HS512 = DEM.register(
            new EncryptThenPRF(StreamCipher.CC20, SHA512.asPRF()));

    private final PRF prf;
    private final StreamCipher cipher;
    private final byte[] subKeyLabel;
    private final byte[] zeroNonce;

    EncryptThenPRF(StreamCipher cipher, PRF prf) {
        this.prf = requireNonNull(prf);
        this.cipher = requireNonNull(cipher);
        this.subKeyLabel = ("Florentine-DEM-" + identifier() + "-SubKeys").getBytes(UTF_8);
        this.zeroNonce = new byte[cipher.nonceSizeBytes()];
    }

    @Override
    DataKey importKey(byte[] keyMaterial) {
        assert keyMaterial.length == 32;
        return new DataKey(HKDF.expand(new DataKey(keyMaterial, "HMAC"), subKeyLabel, 64), identifier());
    }

    @Override
    DataKey encapsulate(SecretKey key, List<Florentine.Record> records) {
        var tag = validateKey(key);
        for (var record : records) {
            tag = encryptRecord(tag, record);
        }
        return new DataKey(tag, identifier());
    }

    private byte[] encryptRecord(byte[] keyMaterial, Florentine.Record record) {
        assert keyMaterial.length == 64;

        try (var macKey = new DataKey(keyMaterial,  0, 32, prf.algorithm());
             var encKey = new DataKey(keyMaterial, 32, 64, cipher.algorithm())) {
            if (record.isEncrypted()) {
                // Key is unique for each record, so can use a simple 0 nonce.
                cipher.cipher(encKey, zeroNonce, record.content());
            }
            return prf.apply(macKey, record.header(), record.content());
        }
    }

    @Override
    Optional<DataKey> decapsulate(SecretKey key, List<Florentine.Record> records, byte[] expectedTag) {
        if (expectedTag.length != 16) {
            return Optional.empty();
        }

        var tag = validateKey(key);
        for (var record : records) {
            tag = decryptRecord(tag, record);
        }

        var caveatKey = new DataKey(tag, identifier());
        var computedTag = tag(caveatKey);
        if (!MessageDigest.isEqual(computedTag, expectedTag)) {
            CryptoUtils.wipe(computedTag, tag);
            for (var part : records) {
                CryptoUtils.wipe(part.content());
            }
            return Optional.empty();
        }

        CryptoUtils.wipe(computedTag, tag);
        return Optional.of(caveatKey);
    }

    private byte[] decryptRecord(byte[] keyMaterial, Florentine.Record record) {
        assert keyMaterial.length == 64;

        try (var macKey = new DataKey(keyMaterial,  0, 32, prf.algorithm());
             var encKey = new DataKey(keyMaterial, 32, 64, cipher.algorithm())) {
            var tag = prf.apply(macKey, record.header(), record.content());
            if (record.isEncrypted()) {
                // Key is unique for each record, so can use a simple 0 nonce.
                cipher.cipher(encKey, zeroNonce, record.content());
            }
            return tag;
        }
    }

    @Override
    public String identifier() {
        return cipher.identifier() + "-" + prf.identifier();
    }

    @Override
    KeyWrapper asKeyWrapper() {
        return new SivMode(identifier().replaceAll("(CTR)?-", "SIV-"), cipher, prf);
    }

    private byte[] validateKey(SecretKey key) {
        var keyBytes = key.getEncoded();
        if (!identifier().equals(key.getAlgorithm()) || keyBytes == null || keyBytes.length != 64) {
            throw new IllegalArgumentException("invalid key");
        }
        return keyBytes;
    }

}
