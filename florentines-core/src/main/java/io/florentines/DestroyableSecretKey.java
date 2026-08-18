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

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

/**
 * An implementation of {@link SecretKey} that actually implements the {@link Destroyable} methods,
 * rather than throwing an exception.
 */
public class DestroyableSecretKey implements SecretKey, AutoCloseable {
    private final String algorithm;
    private final byte[] keyMaterial;
    private volatile boolean destroyed;
    private final int hashCode;

    public DestroyableSecretKey(String algorithm, byte[] keyMaterial, int offset, int length) {
        this.algorithm = Require.notBlank(algorithm, "algorithm");
        this.keyMaterial = Arrays.copyOfRange(keyMaterial, offset, offset + length);

        // For compatibility with SecretKeySpec
        this.hashCode = Arrays.hashCode(keyMaterial) ^ algorithm.toLowerCase(Locale.ENGLISH).hashCode();
    }

    public DestroyableSecretKey(String algorithm, byte[] keyMaterial) {
        this(algorithm, keyMaterial, 0, keyMaterial.length);
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
        if (isDestroyed()) { throw new IllegalStateException("key has been destroyed"); }
        return keyMaterial.clone();
    }

    @Override
    public void destroy() {
        Arrays.fill(keyMaterial, (byte) 0);
        destroyed = true;
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
    public int hashCode() {
        if (isDestroyed()) { throw new IllegalStateException("key has been destroyed"); }

        return hashCode;
    }

    @Override
    public boolean equals(Object other) {
        if (isDestroyed()) { throw new IllegalStateException("key has been destroyed"); }

        if (this == other) { return true; }
        if (!(other instanceof SecretKey that)) { return false; }
        var thatKeyMaterial = that.getEncoded();
        try {
            return this.algorithm.equalsIgnoreCase(that.getAlgorithm()) &&
                    MessageDigest.isEqual(this.keyMaterial, thatKeyMaterial);
        } finally {
            Arrays.fill(thatKeyMaterial, (byte) 0);
        }
    }

    @Override
    public String toString() {
        return "DestroyableSecretKey{" +
                "algorithm='" + algorithm + '\'' +
                ", keyMaterial.length=" + keyMaterial.length +
                ", destroyed=" + destroyed +
                '}';
    }
}
