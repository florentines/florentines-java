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

package io.florentines;

import java.util.HexFormat;

final class Utils {

    static String hex(byte[] data) {
        return HexFormat.of().formatHex(data);
    }

    static byte[] reverseInPlace(byte[] data) {
        for (int i = 0; i < data.length / 2; ++i) {
            swap(data, i, data.length - i - 1);
        }
        return data;
    }

    static void swap(byte[] arr, int i, int j) {
        byte tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }

    private Utils() {
        throw new UnsupportedOperationException("utility class");
    }
}
