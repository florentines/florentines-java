/*
 * Copyright 2025-2026 Neil Madden.
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

import io.florentine.DestroyableSecretKey;

public interface HMAC {

    int getKeyLengthBytes();
    int getTagLengthBytes();
    HmacKey importKey(byte[] keyMaterial, int offset);
    byte[] process(HmacKey key, byte[] data);

    default byte[] cascade(HmacKey key, Iterable<byte[]> data) {
        byte[] tag = null;
        for (var datum : data) {
            tag = process(key, datum);
            // Overwrite and reuse the existing key object to avoid unnecessary allocations
            System.arraycopy(tag, 0, key.keyMaterial(), 0, key.keyMaterial().length);
        }
        key.destroy();
        assert tag != null;
        return tag;
    }

    final class HmacKey extends DestroyableSecretKey {
        HmacKey(byte[] keyMaterial, int offset, int length, String algorithm) {
            super(keyMaterial, offset, length, algorithm);
        }

        HmacKey(byte[] keyMaterial, String algorithm) {
            super(keyMaterial, algorithm);
        }

        byte[] keyMaterial() {
            if (isDestroyed()) {
                throw new IllegalStateException("key has been destroyed");
            }
            return keyMaterial;
        }
    }
}
