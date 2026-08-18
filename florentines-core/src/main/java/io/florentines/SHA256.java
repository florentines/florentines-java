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

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

final class SHA256 {

    static byte[] hmac(SecretKey key, byte[] data) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static byte[] hmacCascade(DestroyableSecretKey key, byte[]... data) {
        assert data.length > 0;
        byte[] tag = null;
        for (var datum : data) {
            tag = hmac(key, datum);
            System.arraycopy(tag, 0, key.rawKeyMaterial(), 0, 16);
        }
        return tag;
    }
}
