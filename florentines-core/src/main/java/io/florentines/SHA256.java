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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Utilities based on the SHA-256 cryptographic hash function.
 */
final class SHA256 {

    static byte[] hash(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Computes a Hash-based Message Authentication Code (HMAC) using SHA-256.
     *
     * @param key the secret key for the MAC.
     * @param data the data to be authenticated.
     * @return the 32-byte HMAC-SHA-256 authentication tag.
     */
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

    /**
     * Computes a HMAC tag over an arbitrary collection of input data byte arrays using a <em>cascade</em> construction.
     * The final tag is computed as if by the following code:
     * <pre>{@code
     * var tag = key.getEncoded();
     * for (var datum : data) {
     *     tag = hmac(key(tag), datum);
     * }
     * }</pre>
     * This construction ensures that each block of data is treated as logically separated from any other. For example,
     * the tag computed for the blocks {@code [1, 2], [3]} is distinct from that for {@code [1], [2, 3]}.
     *
     * @param key the initial secret key. It will be destroyed before the routine returns.
     * @param data one or more data blocks to authenticate. Must not be empty.
     * @return the computed aggregate HMAC tag.
     */
    static byte[] hmacCascade(DestroyableSecretKey key, List<byte[]> data) {
        Require.notEmpty(data, "data");
        byte[] tag = null;
        for (var datum : data) {
            tag = hmac(key, datum);
            key.overwrite(tag);
        }
        key.destroy();
        return tag;
    }
}
