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

abstract class PRF implements BiFunction<byte[], byte[], byte[]> {
    static final PRF HS512 = new HS512();

    abstract String identifier();
    abstract byte[] calculate(byte[] key, byte[] data);

    @Override
    public byte[] apply(byte[] key, byte[] data) {
        return calculate(key, data);
    }

    @SafeVarargs
    final byte[] cascade(byte[] key, Iterable<byte[]>... records) {
        assert records.length > 0;
        for (var data : records) {
            for (var datum : data) {
                key = calculate(key, datum);
            }
        }
        return key;
    }
}
