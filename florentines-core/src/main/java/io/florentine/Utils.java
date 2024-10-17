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

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * General utility methods.
 */
final class Utils {
    private static final Logger logger = LoggerFactory.getLogger(Utils.class);
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    static byte[] emptyBytes() {
        return EMPTY_BYTE_ARRAY;
    }

    static <T> ThreadLocal<T> threadLocal(Callable<T> supplier) {
        return ThreadLocal.withInitial(() -> {
            try {
                return supplier.call();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    static byte[] unsignedLittleEndian(BigInteger i) {
        var bytes = i.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            // Strip leading sign byte
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return reverse(bytes);
    }

    static byte[] reverse(byte[] data) {
        int len = data.length;
        for (int i = 0; i < len/2; ++i) {
            byte tmp = data[i];
            data[i] = data[len - i - 1];
            data[len - i - 1] = tmp;
        }
        return data;
    }

    static void destroy(Destroyable... toDestroy) {
        Arrays.stream(toDestroy).forEach(it -> {
            try {
                it.destroy();
            } catch (DestroyFailedException e) {
                logger.error("Unable to destroy key material: {}", it, e);
            } catch (RuntimeException e) {
                logger.error("Unexpected runtime exception while destroying key: {}", it, e);
            }
        });
    }

    static void wipe(byte[]... toWipe) {
        wipe(List.of(toWipe));
    }

    static void wipe(Iterable<byte[]> toWipe) {
        for (var it : toWipe) {
            if (it != null) {
                Arrays.fill(it, (byte) 0);
            }
        }
    }

    static byte[] concat(byte[]... elements) {
        int totalSize = Arrays.stream(elements).mapToInt(x -> x.length).sum();
        var result = new byte[totalSize];
        int i = 0;
        for (var element : elements) {
            System.arraycopy(element, 0, result, i, element.length);
            i += element.length;
        }
        assert i == totalSize;
        return result;
    }

    private Utils() {}
}
