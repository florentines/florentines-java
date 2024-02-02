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

package io.florentine.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

final class CryptoUtils {
    private static final SecureRandom SECURE_RANDOM;

    static {
        SecureRandom random;
        try {
            random = SecureRandom.getInstance("NativePRNGNonBlocking");
        } catch (NoSuchAlgorithmException e) {
            random = new SecureRandom();
        }
        SECURE_RANDOM = random;
    }

    static void destroy(Destroyable... toDestroy) {
        for (var it : toDestroy) {
            if (!it.isDestroyed()) {
                try {
                    it.destroy();
                } catch (DestroyFailedException e) {
                    // Ignore - default behaviour of keys is to not be destroyable unfortunately
                }
            }
        }
    }

    static void wipe(byte[] data) {
        Arrays.fill(data, (byte) 0);
    }

    static boolean allZero(byte[] data) {
        int check = 0;
        for (byte b : data) {
            check |= b;
        }
        return check == 0;
    }

    static byte[] randomBytes(int numBytes) {
        byte[] bytes = new byte[numBytes];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    static byte[] concat(byte[]... elements) {
        int totalSize = Arrays.stream(elements).mapToInt(b -> b.length).reduce(0, Math::addExact);
        byte[] result = new byte[totalSize];
        int offset = 0;
        for (var element : elements) {
            System.arraycopy(element, 0, result, offset, element.length);
            offset += element.length;
        }
        return result;
    }

    private CryptoUtils() {}
}
