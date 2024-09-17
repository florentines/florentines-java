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

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class CC20HS512 extends DEM {
    private static final byte[] ZERO_NONCE = new byte[12];
    private static final ThreadLocal<Cipher> CIPHER_THREAD_LOCAL =
            ThreadLocal.withInitial(() -> {
                try {
                    return Cipher.getInstance("ChaCha20");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new UnsupportedOperationException(e);
                }
            });
    private static final ThreadLocal<Mac> MAC_THREAD_LOCAL =
            ThreadLocal.withInitial(() -> {
                try {
                    return Mac.getInstance("HmacSHA512");
                } catch (NoSuchAlgorithmException e) {
                    throw new UnsupportedOperationException(e);
                }
            });

    @Override
    byte[] encapsulate(byte[] key, Iterable<? extends Record> records) {
        Require.notEmpty(records, "Must provide at least one record");
        for (var record : records) {
            var macKey = encrypt(key, record.content());
            key = hmac(macKey, record.assocData(), record.content());
        }
        return key;
    }

    @Override
    Optional<byte[]> decapsulate(byte[] key, Iterable<? extends Record> records, byte[] tag) {
        Require.notEmpty(records, "Must provide at least one record");
        boolean valid = false;
        try {
            for (var record : records) {
                var content = record.content();
                var cipher = cipher(key);
                var macKey = cipher.update(new byte[32]);
                key = hmac(macKey, record.assocData(), content);
                cipher.update(content, 0, content.length, content);
            }
            valid = MessageDigest.isEqual(key, tag);
        } catch (ShortBufferException e) {
            throw new AssertionError("Errr...", e);
        } finally {
            if (!valid) {
                // Avoid releasing unverified plaintext
                for (var record : records) {
                    Arrays.fill(record.content(), (byte) 0);
                }
            }
        }

        return valid ? Optional.of(key) : Optional.empty();
    }

    private Cipher cipher(byte[] key) {
        var cipher = CIPHER_THREAD_LOCAL.get();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"),
                    new ChaCha20ParameterSpec(ZERO_NONCE, 0));
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

    private byte[] hmac(byte[] macKey, byte[]... data) {
        assert data.length > 0;
        var mac = MAC_THREAD_LOCAL.get();
        for (var datum : data) {
            try {
                mac.init(new SecretKeySpec(macKey, 0, 32, "HmacSHA512"));
                macKey = Arrays.copyOf(mac.doFinal(datum), 32);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }
        return macKey;
    }
}
