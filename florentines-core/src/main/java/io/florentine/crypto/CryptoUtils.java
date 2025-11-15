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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class CryptoUtils {
    private CryptoUtils() {}

    private static final ThreadLocal<MessageDigest> SHA512 = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("mandatory algorithm", e);
        }
    });

    public static void wipe(byte[]... toWipe) {
        for (var data : toWipe) {
            if (data != null) {
                Arrays.fill(data, (byte) 0);
            }
        }
    }

    public static boolean allZero(byte[] bytes) {
        int sum = 0;
        for (var b : bytes) {
            sum |= b;
        }
        return sum == 0;
    }

    public static byte[] hash(byte[] data) {
        return Arrays.copyOf(SHA512.get().digest(data), 32);
    }
}
