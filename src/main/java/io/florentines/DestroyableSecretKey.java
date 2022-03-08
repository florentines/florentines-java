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

import static java.util.Objects.checkFromIndexSize;
import static java.util.Objects.requireNonNull;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.SecretKey;

/**
 * Represents a secret key as an in-memory byte array. This is similar to {@link javax.crypto.spec.SecretKeySpec},
 * except that the {@link #destroy()} method actually works (it scrubs the key material from memory).
 */
public final class DestroyableSecretKey implements SecretKey {

    private final String algorithm;
    private final String format;
    private final byte[] keyMaterial;
    private volatile boolean destroyed = false;

    public DestroyableSecretKey(String algorithm, String format, byte[] keyMaterial, int offset, int length) {
        this.algorithm = requireNonNull(algorithm, "algorithm");
        this.format = requireNonNull(format, "format");
        checkFromIndexSize(offset, length, requireNonNull(keyMaterial, "keyMaterial").length);
        this.keyMaterial = Arrays.copyOfRange(keyMaterial, offset, offset + length);
    }

    public DestroyableSecretKey(String algorithm, String format, byte[] keyMaterial) {
        this(algorithm, format, keyMaterial, 0, requireNonNull(keyMaterial, "keyMaterial").length);
    }

    public DestroyableSecretKey(String algorithm, byte[] keyMaterial) {
        this(algorithm, "RAW", keyMaterial);
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return format;
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        return keyMaterial.clone();
    }

    @Override
    public void destroy() {
        destroyed = true;
        Arrays.fill(keyMaterial, (byte) 0);
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public boolean equals(Object other) {
        checkDestroyed();
        if (this == other) { return true; }
        if (!(other instanceof DestroyableSecretKey)) { return false; }
        DestroyableSecretKey that = (DestroyableSecretKey) other;
        return algorithm.equals(that.algorithm) && format.equals(that.format)
                && MessageDigest.isEqual(keyMaterial, that.keyMaterial);
    }

    @Override
    public int hashCode() {
        checkDestroyed();
        byte[] hash = HKDF.extract(keyMaterial, new byte[32]);
        int result = Objects.hash(algorithm, format, destroyed);
        result = 31 * result + Arrays.hashCode(hash);
        return result;
    }

    @Override
    public String toString() {
        return "DestroyableSecretKey{" +
                "algorithm='" + algorithm + '\'' +
                ", format='" + format + '\'' +
                ", destroyed=" + destroyed +
                '}';
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("Key material has been destroyed");
        }
    }
}
