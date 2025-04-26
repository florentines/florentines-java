/*
 * Copyright 2025 Neil Madden.
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

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

final class HKDF {

    private static final ThreadLocal<Mac> MAC_THREAD_LOCAL = ThreadLocal.withInitial(() -> {
        try {
            return Mac.getInstance("HmacSHA512");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    });

    static DestroyableSecretKey extract(byte[] ikm, byte[] salt) {
        var hmac = MAC_THREAD_LOCAL.get();
        try (var k = new DestroyableSecretKey(salt, hmac.getAlgorithm())) {
            hmac.init(k);
            return new DestroyableSecretKey(hmac.doFinal(ikm), hmac.getAlgorithm());
        } catch (InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    static byte[] expand(SecretKey prk, byte[] info, int numBytes) {
        assert numBytes >= 0 && numBytes < 255 * 64 : "invalid number of bytes requested";
        var hmac = MAC_THREAD_LOCAL.get();
        try (var out = new ByteArrayOutputStream(numBytes)) {
            hmac.init(prk);
            int remaining = numBytes;
            int numBlocks = (numBytes + 63) / 64;
            byte[] lastBlock = new byte[0];

            for (int i = 1; i <= numBlocks; ++i) {
                hmac.update(lastBlock);
                hmac.update(info);
                hmac.update((byte) i);
                lastBlock = hmac.doFinal();
                out.write(lastBlock, 0, Math.min(64, remaining));
                remaining -= 64;
            }

            return out.toByteArray();
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (IOException e) {
            throw new AssertionError("shouldn't happen", e);
        }
    }
}
