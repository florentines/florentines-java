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

package io.florentine.crypto;

import org.apache.commons.codec.digest.Blake3;

public final class Blake3PRF implements PseudoRandomFunction {
    public static final Blake3PRF B3512 = new Blake3PRF(64);

    private final int tagLengthBytes;
    private final String algorithm;

    Blake3PRF(int tagLengthBytes) {
        this.tagLengthBytes = tagLengthBytes;
        this.algorithm = "B3" + (tagLengthBytes * 8);
    }

    @Override
    public int getKeyLengthBytes() {
        return 32;
    }

    @Override
    public int getTagLengthBytes() {
        return tagLengthBytes;
    }

    @Override
    public DestroyableSecretKey importKey(byte[] keyMaterial, int offset) {
        return new DestroyableSecretKey(keyMaterial, offset, offset+32, algorithm);
    }

    @Override
    public byte[] process(DestroyableSecretKey key, byte[] data) {
        if (!key.getAlgorithm().endsWith(algorithm)) {
            throw new IllegalArgumentException("invalid key");
        }
        return Blake3.initKeyedHash(key.keyMaterial()).update(data).doFinalize(tagLengthBytes);
    }
}
