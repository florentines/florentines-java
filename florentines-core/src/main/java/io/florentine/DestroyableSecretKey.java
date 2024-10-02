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

import static java.util.Objects.requireNonNull;

import java.util.Arrays;
import java.util.Locale;

import javax.crypto.SecretKey;

import software.pando.crypto.nacl.Bytes;

/**
 * A drop-in replacement for {@link javax.crypto.spec.SecretKeySpec} where the {@link #destroy()} method actually works.
 */
public final class DestroyableSecretKey implements SecretKey, AutoCloseable {

    private volatile boolean destroyed = false;

    private final String algorithm;
    private final byte[] keyBytes;

    public DestroyableSecretKey(byte[] key, String algorithm) {
        this(key, 0, key.length, algorithm);
    }

    public DestroyableSecretKey(byte[] key, int offset, int len, String algorithm) {
        this.algorithm = requireNonNull(algorithm, "algorithm");
        this.keyBytes = Arrays.copyOfRange(key, offset, offset + len);
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
        return getKeyBytes().clone();
    }

    byte[] getKeyBytes() {
        if (destroyed) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return keyBytes; // No defensive copy
    }

    @Override
    public void destroy() {
        Arrays.fill(keyBytes, (byte) 0);
        this.destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof SecretKey that)) {
            return false;
        }
        if (this.isDestroyed() || that.isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        if (!this.getAlgorithm().equalsIgnoreCase(that.getAlgorithm())) {
            return false;
        }
        if (!"RAW".equals(that.getFormat())) {
            return false;
        }
        byte[] otherKeyBytes = that.getEncoded();
        try {
            return Bytes.equal(this.keyBytes, otherKeyBytes);
        } finally {
            Arrays.fill(otherKeyBytes, (byte) 0);
        }
    }

    @Override
    public int hashCode() {
        // Compatible with SecretKeySpec.hashCode()
        int retval = 0;
        for (int i = 1; i < this.keyBytes.length; i++) {
            retval += this.keyBytes[i] * i;
        }
        return retval ^ this.algorithm.toLowerCase(Locale.ENGLISH).hashCode();
    }

    @Override
    public String toString() {
        return "DataEncapsulationKey{" +
                "destroyed=" + destroyed +
                ", algorithm='" + algorithm + '\'' +
                ", bits=" + keyBytes.length * 8 +
                '}';
    }
}
