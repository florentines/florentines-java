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

    @Override
    public int getKeyLengthBytes() {
        return 32;
    }

    @Override
    public int getTagLengthBytes() {
        return 64;
    }

    @Override
    public DestroyableSecretKey importKey(byte[] keyMaterial, int offset) {
        return new DestroyableSecretKey(keyMaterial, offset, offset+32, "Blake2b-512");
    }

    @Override
    public byte[] process(DestroyableSecretKey key, byte[] data) {
        var hash = new Blake2b(key.getEncoded());
        hash.update(data, 0, data.length);
        var out = new byte[64];
        int size = hash.digest(out, 0);
        assert size == 64;
        return out;
    }
}
