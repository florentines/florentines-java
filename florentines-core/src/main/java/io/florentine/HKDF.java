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

import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.Mac;

/**
 * An implementation of <a href="https://www.rfc-editor.org/rfc/rfc5869">HKDF</a>
 * using SHA-512 as the underlying hash function.
 */
final class HKDF {
    private static final ThreadLocal<Mac> MAC_THREAD_LOCAL = threadLocal(() -> Mac.getInstance("HmacSHA512"));

    static byte[] extract(byte[] salt, byte[] ikm) {
        return hmac(salt, ikm);
    }

    static byte[] expand(byte[] prk, byte[] info, int numBytes) {
        Require.between(numBytes, 0, 255*64, "Can only generate between 0 and 16,320 bytes of output");
        var output = new byte[numBytes];
        var last = new byte[0];
        var counter = new byte[1];
        int left = numBytes;
        for (int i = 1; i < ((numBytes + 63) / 64); ++i) {
            counter[0] = (byte) i;
            last = hmac(prk, last, info, counter);
            System.arraycopy(last, 0, output, i*64, Math.min(left, 64));
            left -= 64;
        }
        assert left <= 0;
        return output;
    }

    static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int numBytes) {
        var prk = extract(salt, ikm);
        try {
            return expand(prk, info, numBytes);
        } finally {
            Arrays.fill(prk, (byte) 0);
            Arrays.fill(ikm, (byte) 0);
        }
    }

    static byte[] hmac(byte[] key, byte[]... data) {
        var mac = MAC_THREAD_LOCAL.get();
        try (var k = new DestroyableSecretKey(key, mac.getAlgorithm())) {
            mac.init(k);
            for (var datum : data) {
                mac.update(datum);
            }
            return mac.doFinal();
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}
