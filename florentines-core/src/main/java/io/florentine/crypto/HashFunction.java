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

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public final class HashFunction {
    public static final HashFunction SHA512 = new HashFunction("SHA-512");

    private final String algorithmName;

    public HashFunction(String algorithmName) {
        this.algorithmName = algorithmName;
        try {
            MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] hash(byte[] data) {
        try {
            var hash = MessageDigest.getInstance(algorithmName);
            return hash.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public PRF asPRF(int tagSizeBytes) {
        return new Hmac("Hmac" + algorithmName.replace("-", ""), tagSizeBytes);
    }

    public PRF asPRF() {
        return asPRF(PRF.OUTPUT_SIZE_BYTES);
    }

    private static class Hmac implements PRF {
        private final String algorithmName;
        private final int tagSize;

        private Hmac(String algorithmName, int tagSize) {
            this.algorithmName = algorithmName;
            this.tagSize = tagSize;
            try {
                Mac.getInstance(algorithmName);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException(e);
            }
        }

        @Override
        public String algorithm() {
            return algorithmName;
        }

        @Override
        public byte[] apply(SecretKey key, byte[] data) {
            try {
                var hmac = Mac.getInstance(algorithmName);
                hmac.init(key);
                var tag = hmac.doFinal(data);
                return Arrays.copyOf(tag, tagSize);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            } catch (InvalidKeyException e) {
                throw new IllegalArgumentException(e);
            }
        }
    }
}
