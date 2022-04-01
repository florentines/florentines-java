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

import static software.pando.crypto.nacl.Crypto.auth;
import static software.pando.crypto.nacl.Crypto.authKey;

import java.util.function.BiFunction;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

@FunctionalInterface
interface PRF extends BiFunction<SecretKey, byte[], SecretKey> {
    PRF HS256 = (key, data) -> {
        try {
            return authKey(auth(key, data));
        } finally {
            try {
                key.destroy();
            } catch (DestroyFailedException e) {
                // Ignore
            }
        }
    };
}
