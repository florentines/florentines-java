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

import static io.florentine.HKDF.hmac;

import java.util.Arrays;

/**
 * Implements HMAC-SHA-512-256. That is, HMAC-SHA-512 truncated to the first 256 bits of output.
 */
final class HS512 implements PRF {
    public static final int TAG_SIZE_BYTES = 32;

    @Override
    public byte[] calculate(byte[] keyBytes, byte[] data) {
        return Arrays.copyOf(hmac(keyBytes, data), TAG_SIZE_BYTES);
    }
}
