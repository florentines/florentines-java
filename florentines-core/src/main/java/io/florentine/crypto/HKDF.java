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

package io.florentine.crypto;

import static io.florentine.crypto.HashFunction.SHA512;

final class HKDF {
    private static final PRF hmac = SHA512.asPRF(64);

    static DestroyableSecretKey extract(byte[] salt, byte[] inputKeyMaterial) {
        try (var key = new DestroyableSecretKey(salt, hmac.algorithm())) {
            return new DestroyableSecretKey(hmac.apply(key, inputKeyMaterial), hmac.algorithm());
        }
    }

    static byte[] expand(DestroyableSecretKey prk, byte[] context, int outputSizeBytes) {
        int rounds = (outputSizeBytes + 63) / 64;
        if (rounds > 255) {
            throw new IllegalArgumentException("output size exceeds limit");
        }
        byte[] lastBlock = new byte[0];
        byte[] counter = new byte[] { 1 };
        var out = new byte[outputSizeBytes];
        while (outputSizeBytes > 0) {
            var input = CryptoUtils.concat(lastBlock, context, counter);
            lastBlock = hmac.apply(prk, input);
            System.arraycopy(lastBlock, 0, out, ((counter[0] - 1) * 64), Math.min(64, outputSizeBytes));
            outputSizeBytes -= 64;
            counter[0]++;
        }
        return out;
    }

    static DestroyableSecretKey expandToKey(DestroyableSecretKey prk, byte[] context, int outputSizeBytes,
                                            String keyAlgorithm) {
        return new DestroyableSecretKey(expand(prk, context, outputSizeBytes), keyAlgorithm);
    }

}
