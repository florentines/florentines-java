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

import static io.florentine.Utils.threadLocal;

import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.Mac;

final class HS512 implements PRF {
    private static final ThreadLocal<Mac> MAC_THREAD_LOCAL = threadLocal(() -> Mac.getInstance("HmacSHA512"));

    @Override
    public byte[] calculate(byte[] keyBytes, byte[] data) {
        var hmac = MAC_THREAD_LOCAL.get();
        try (var key = new DestroyableSecretKey(keyBytes, hmac.getAlgorithm())) {
            hmac.init(key);
            return Arrays.copyOf(hmac.doFinal(data), 32);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
