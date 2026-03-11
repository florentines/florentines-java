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

import com.rfksystems.blake2b.Blake2b;

public final class Blake2bPRF implements PseudoRandomFunction {
    public static final Blake2bPRF B2512 = new Blake2bPRF();
    private static final String ALGORITHM = "B2512";
    private static final int TAG_LENGTH_BYTES = 64;
    private static final int KEY_LENGTH_BYTES = 32;

    @Override
    public int getKeyLengthBytes() {
        return KEY_LENGTH_BYTES;
    }

    @Override
    public int getTagLengthBytes() {
        return TAG_LENGTH_BYTES;
    }

    @Override
    public DestroyableSecretKey importKey(byte[] keyMaterial, int offset) {
        return new DestroyableSecretKey(keyMaterial, offset, offset + KEY_LENGTH_BYTES, ALGORITHM);
    }

    @Override
    public byte[] process(DestroyableSecretKey key, byte[] data) {
        if (!key.getAlgorithm().endsWith(ALGORITHM)) {
            throw new IllegalArgumentException("invalid key");
        }

        var hash = new Blake2b(key.keyMaterial());
        hash.update(data, 0, data.length);
        var out = new byte[TAG_LENGTH_BYTES];
        int size = hash.digest(out, 0);
        assert size == TAG_LENGTH_BYTES;
        return out;
    }
}
