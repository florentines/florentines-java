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

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.SecretKey;

record DestroyableSecretKey(byte[] keyMaterial, int from, int to, String algorithm) implements SecretKey,
        AutoCloseable {

    public DestroyableSecretKey(byte[] keyMaterial, String algorithm) {
        this(keyMaterial, 0, keyMaterial.length, algorithm);
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key material has been destroyed");
        }
        return Arrays.copyOfRange(keyMaterial, from, to);
    }

    @Override
    public void destroy() {
        Arrays.fill(keyMaterial, from, to, (byte) 0);
    }

    @Override
    public boolean isDestroyed() {
        return CryptoUtils.allZero(Arrays.copyOfRange(keyMaterial, from, to));
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public int hashCode() {
        // Designed to be compatible with SecretKeySpec.hashCode()
        int retval = 0;
        for (int i = 1; i < this.keyMaterial.length; i++) {
            retval += this.keyMaterial[i] * i;
        }
        return retval ^ this.algorithm.toLowerCase(Locale.ENGLISH).hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        // Designed to be compatible with SecretKeySpec.equals()
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SecretKey that) || !that.getAlgorithm().equalsIgnoreCase(this.algorithm)) {
            return false;
        }

        byte[] thatKey = that.getEncoded();
        try {
            return MessageDigest.isEqual(this.keyMaterial, thatKey);
        } finally {
            CryptoUtils.wipe(thatKey);
        }
    }
}
