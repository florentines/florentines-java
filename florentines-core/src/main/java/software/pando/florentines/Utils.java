/*
 * Copyright 2022 Neil Madden.
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

package software.pando.florentines;

import java.util.Arrays;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

final class Utils {

    /**
     * Reverses the given byte array in-place and returns it.
     *
     * @param data the data to reverse.
     * @return the reversed array.
     */
    static byte[] reverse(byte[] data) {
        for (int i = 0; i < data.length/2; ++i) {
            byte tmp = data[i];
            data[i] = data[data.length - i - 1];
            data[data.length - i - 1] = tmp;
        }
        return data;
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] combined = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, combined, a.length, b.length);
        return combined;
    }


    static void destroy(Destroyable... keys) {
        for (var key : keys) {
            if (key != null && !key.isDestroyed()) {
                try {
                    key.destroy();
                } catch (DestroyFailedException e) {
                    // Ignore
                }
            }
        }
    }

    private Utils() {}
}
