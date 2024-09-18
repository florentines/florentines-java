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

import java.util.concurrent.Callable;

/**
 * General utility methods.
 */
final class Utils {
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

    private Utils() {}
}
