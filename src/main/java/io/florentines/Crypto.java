/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines;

import static io.florentines.Utils.allZero;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;

final class Crypto {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    static final String HMAC_ALGORITHM = "HmacSHA256";
    static final String HASH_ALGORITHM = "SHA-256";
    static final int HMAC_TAG_SIZE_BYTES = 32;

    static byte[] hmac(Key key, byte[]... data) {
        try {
            assert !allZero(key.getEncoded());
            var hmac = Mac.getInstance(HMAC_ALGORITHM);
            hmac.init(key);
            for (byte[] block : data) {
                hmac.update(block);
            }
            return hmac.doFinal();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static DestroyableSecretKey hmacKey(byte[] keyData) {
        try {
            return new DestroyableSecretKey(HMAC_ALGORITHM, keyData);
        } finally {
            Utils.wipe(keyData);
        }
    }

    static byte[] hash(byte[] data) {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] randomBytes(int numBytes) {
        byte[] bytes = new byte[numBytes];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }
}
