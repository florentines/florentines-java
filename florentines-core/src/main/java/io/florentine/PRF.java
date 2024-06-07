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

import java.util.function.BiFunction;

import javax.crypto.SecretKey;

interface PRF extends BiFunction<SecretKey, byte[][], byte[]> {

    byte[] apply(SecretKey key, byte[]... data);
    String algorithm();
    String identifier();

    default byte[] applyMulti(SecretKey key, Iterable<byte[]> blocks) {
        byte[] tag = null;
        for (byte[] block : blocks) {
            var intermediateKey = tag != null;
            tag = apply(key, block);
            if (intermediateKey) {
                // Destroy intermediate keys after use
                CryptoUtils.destroy(key);
            }
            key = new DataKey(tag, key.getAlgorithm());
        }
        if (tag == null) {
            throw new IllegalArgumentException();
        }
        tag = tag.clone();
        CryptoUtils.destroy(key);
        return tag;
    }
}
