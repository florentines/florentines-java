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

import static io.florentines.Crypto.HMAC_TAG_SIZE_BYTES;
import static io.florentines.Crypto.hmac;
import static io.florentines.Crypto.hmacKey;

import java.security.Key;

final class HKDF {

    static DestroyableSecretKey extract(byte[] inputKeyMaterial, byte[] salt) {
        return hmacKey(hmac(hmacKey(salt.clone()), inputKeyMaterial));
    }

    static DestroyableSecretKey extract(byte[] ikm1, byte[] ikm2, byte[] salt) {
        return hmacKey(hmac(hmacKey(salt), ikm1, ikm2));
    }

    static byte[] expand(Key prk, byte[] context, int outputKeySizeBytes) {
        if (outputKeySizeBytes <= 0 || outputKeySizeBytes > 255 * HMAC_TAG_SIZE_BYTES) {
            throw new IllegalArgumentException("Output size must be >= 1 and <= " + 255 * HMAC_TAG_SIZE_BYTES);
        }
        byte[] last = new byte[0];
        byte[] counter = new byte[1];
        byte[] output = new byte[outputKeySizeBytes];
        for (int i = 0; i < outputKeySizeBytes; i += HMAC_TAG_SIZE_BYTES) {
            counter[0]++;
            last = hmac(prk, last, context, counter);
            System.arraycopy(last, 0, output, i, Math.min(outputKeySizeBytes - i, HMAC_TAG_SIZE_BYTES));
        }
        return output;
    }
}
