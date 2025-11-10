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

import io.florentine.dem.DataKey;

public interface PseudoRandomFunction {

    int tagLen();
    DataKey importKey(byte[] keyMaterial, int offset);
    byte[] process(DataKey key, byte[] data);

    default byte[] cascade(DataKey key, Iterable<byte[]> data) {
        byte[] tag = null;
        for (var datum : data) {
            tag = process(key, datum);
            key.destroy();
            key = importKey(tag, 0);
        }
        assert tag != null;
        return tag;
    }
}
