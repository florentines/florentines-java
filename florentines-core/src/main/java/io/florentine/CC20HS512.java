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

import static io.florentine.Utils.threadLocal;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.ChaCha20ParameterSpec;

final class CC20HS512 extends DEM {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final byte[] ZERO_NONCE = new byte[12];
    private static final ThreadLocal<Cipher> CIPHER_THREAD_LOCAL = threadLocal(() -> Cipher.getInstance("ChaCha20"));
    private static final ThreadLocal<Mac> MAC_THREAD_LOCAL = threadLocal(() -> Mac.getInstance("HmacSHA512"));
    private static final int TAG_LEN = 32;
    private static final int WRAPPED_TAG_LEN = 16;

    @Override
    public String identifier() {
        return "CC20-HS512";
    }

    @Override
    DestroyableSecretKey generateKey() {
        var bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return new DestroyableSecretKey(bytes, identifier());
    }

    @Override
    byte[] encapsulate(DestroyableSecretKey demKey, Iterable<? extends Record> records) {
        Require.notEmpty(records, "Must provide at least one record");
        var key = validateKey(demKey);
        for (var record : records) {
            var macKey = encrypt(key, record.secretContent());
            key = hmac(macKey, record.assocData(), record.publicContent(), record.secretContent());
        }
        return key;
    }

    @Override
    Optional<byte[]> decapsulate(DestroyableSecretKey demKey, Iterable<? extends Record> records, byte[] tag) {
        Require.notEmpty(records, "Must provide at least one record");
        boolean valid = false;
        var key = validateKey(demKey);
        try {
            for (var record : records) {
                var content = record.secretContent();
                var cipher = cipher(key);
                var macKey = cipher.update(new byte[32]);
                key = hmac(macKey, record.assocData(), record.publicContent(), content);
                cipher.update(content, 0, content.length, content);
            }
            valid = MessageDigest.isEqual(key, tag);
        } catch (ShortBufferException e) {
            throw new AssertionError("Errr...", e);
        } finally {
            if (!valid) {
                // Avoid releasing unverified plaintext
                for (var record : records) {
                    Arrays.fill(record.secretContent(), (byte) 0);
                }
            }
        }

        return valid ? Optional.of(key) : Optional.empty();
    }

    @Override
    byte[] wrap(DestroyableSecretKey wrapKey, SecretKey keyToWrap) {
        var key = validateKey(wrapKey);
        var keyBytes = keyToWrap.getEncoded();
        try {
            var macKey = encrypt(key, keyBytes);
            var tag = hmac(macKey, keyToWrap.getAlgorithm().getBytes(UTF_8), keyBytes);
            return Utils.concat(Arrays.copyOf(tag, WRAPPED_TAG_LEN), keyBytes);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    @Override
    Optional<DestroyableSecretKey> unwrap(DestroyableSecretKey unwrapKey, byte[] wrappedKey, String keyAlgorithm) {
        var key = validateKey(unwrapKey);
        var cipher = cipher(key);
        var macKey = cipher.update(new byte[32]);
        var providedTag = Arrays.copyOf(wrappedKey, WRAPPED_TAG_LEN);
        wrappedKey = Arrays.copyOfRange(wrappedKey, WRAPPED_TAG_LEN, wrappedKey.length);
        var computedTag = hmac(macKey, keyAlgorithm.getBytes(UTF_8), wrappedKey);

        if (!MessageDigest.isEqual(providedTag, computedTag)) {
            return Optional.empty();
        }

        try {
            cipher.update(wrappedKey, 0, wrappedKey.length, wrappedKey);
        } catch (ShortBufferException e) {
            throw new AssertionError(e);
        }

        return Optional.of(new DestroyableSecretKey(wrappedKey, keyAlgorithm));
    }

    private Cipher cipher(byte[] key) {
        var cipher = CIPHER_THREAD_LOCAL.get();
        try (var demKey = new DestroyableSecretKey(key, "ChaCha20")) {
            cipher.init(Cipher.ENCRYPT_MODE, demKey, new ChaCha20ParameterSpec(ZERO_NONCE, 0));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        return cipher;
    }

    private byte[] encrypt(byte[] key, byte[] message) {
        var cipher = cipher(key);
        var macKey = new byte[32];
        try {
            cipher.update(macKey, 0, macKey.length, macKey);
            cipher.doFinal(message, 0, message.length, message);
            return macKey;
        } catch (GeneralSecurityException e) {
            CIPHER_THREAD_LOCAL.remove();
            throw new RuntimeException(e);
        }
    }

    static byte[] hmac(byte[] macKey, byte[]... data) {
        assert data.length > 0;
        var mac = MAC_THREAD_LOCAL.get();
        for (var datum : data) {
            try (var key = new DestroyableSecretKey(macKey, 0, 32, "HmacSHA512")) {
                mac.init(key);
                macKey = mac.doFinal(datum);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }
        return Arrays.copyOf(macKey, 32);
    }

    private byte[] validateKey(DestroyableSecretKey key) {
        if (!identifier().equals(key.getAlgorithm())) {
            throw new IllegalArgumentException("invalid algorithm");
        }
        var bytes = key.getKeyBytes();
        if (bytes.length != 32) {
            throw new IllegalArgumentException("invalid key");
        }
        return bytes;
    }
}
