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

import java.math.BigInteger;
import java.util.Arrays;

final class Utils {
    static byte[] toUnsignedLittleEndian(BigInteger value) {
        var bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            // Remove sign byte
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        reverse(bytes);
        return bytes;
    }

    static BigInteger fromUnsignedLittleEndian(byte[] littleEndian) {
        reverse(littleEndian);
        return new BigInteger(1, littleEndian);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    private static void reverse(byte[] data) {
        byte tmp;
        for (int i = 0; i < (data.length >>> 1); ++i) {
            tmp = data[i];
            data[i] = data[data.length - i - 1];
            data[data.length - i - 1] = tmp;
        }
    }
}
