/*
 * Copyright 2023 Neil Madden.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.stream.Stream;

public final class Utils {
    private static final Logger logger = LoggerFactory.getLogger(Utils.class);

    static Iterable<byte[]> append(byte[][] init, byte[] last) {
        return () -> Stream.concat(Stream.of(init), Stream.of(last)).iterator();
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] c = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    /**
     * Attempts to destroy the given key material. Any {@link DestroyFailedException}s thrown during the process are
     * ignored, because most Java built-in keys just throw the exception immediately without any attempt to wipe key
     * material from memory. The Salty Coffee library we use for crypto code does implement this correctly.
     *
     * @param toDestroy zero or more keys to destroy.
     */
    public static void destroy(Destroyable... toDestroy) {
        for (var it : toDestroy) {
            try {
                if (!it.isDestroyed()) {
                    it.destroy();
                }
            } catch (DestroyFailedException e) {
                // Ignore: the default behaviour of most Java built-in keys is to just throw DFE immediately.
                logger.debug("Failed to destroy key: {}", it, e);
            }
        }
    }

    public static void checkState(boolean condition, String msg) {
        if (!condition) {
            throw new IllegalStateException(msg);
        }
    }

    public static void rejectIf(boolean condition, String msg) {
        if (condition) {
            throw new IllegalArgumentException(msg);
        }
    }

    static byte[] toUnsignedLittleEndian(BigInteger x, int expectedSize) {
        byte[] bytes = x.toByteArray();
        if (bytes.length > expectedSize && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return reverseInPlace(bytes);
    }

    static byte[] reverseInPlace(byte[] data) {
        int len = data.length;
        for (int i = 0; i < len >>> 1; ++i) {
            byte tmp = data[len - i - 1];
            data[len - i - 1] = data[i];
            data[i] = tmp;
        }
        return data;
    }

    private Utils() {}
}
