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

package io.florentines;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

final class CryptoUtils {
    private static final SecureRandom RANDOM;
    static {
        SecureRandom random;
        try {
            random = SecureRandom.getInstance("NativePRNGNonBlocking");
        } catch (NoSuchAlgorithmException e) {
            random = new SecureRandom();
        }
        RANDOM = random;
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("JRE missing mandatory SHA-256 hash algorithm");
        }
    }

    static void hkdf(byte[] salt, byte[] context, byte[] ikm1, byte[] ikm2, byte[] output) {
        try (var key = new DestroyableSecretKey("HmacSHA256", salt)) {
            var hmac = Mac.getInstance("HmacSHA256");
            hmac.init(key);
            hmac.update(ikm1);
            var prkBytes = hmac.doFinal(ikm2);

            try (var prk = new DestroyableSecretKey("HmacSHA256", prkBytes)) {
                hmac.init(prk);
                hmac.update(context);
                hmac.update((byte) 0x01);
                hmac.doFinal(output, 0);
            } catch (ShortBufferException e) {
                throw new AssertionError(e);
            } finally {
                Arrays.fill(prkBytes, (byte) 0);
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    static byte[] secureRandomBytes(int numBytes) {
        return RANDOM.generateSeed(numBytes);
    }

    static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    private CryptoUtils() {
        throw new UnsupportedOperationException("utility class");
    }
}
