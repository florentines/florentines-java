/*
 * Copyright 2024-2025 Neil Madden.
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

import javax.crypto.SecretKey;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

public final class DestroyableSecretKey implements SecretKey, AutoCloseable {
    private final byte[] keyMaterial;
    private final String algorithm;
    private final int hashCode;

    public DestroyableSecretKey(byte[] keyMaterial, int from, int to, String algorithm) {
        Objects.checkFromToIndex(from, to, keyMaterial.length);
        this.keyMaterial = Arrays.copyOfRange(keyMaterial, from, to);
        if (CryptoUtils.allZero(this.keyMaterial)) {
            throw new IllegalArgumentException("Key cannot be all-zero");
        }
        this.algorithm = algorithm;
        this.hashCode = Objects.hash(
                Arrays.hashCode(CryptoUtils.hash(this.keyMaterial)), algorithm.toLowerCase(Locale.ROOT));
    }

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
        return keyMaterial.clone();
    }

    @Override
    public void destroy() {
        Arrays.fill(keyMaterial, (byte) 0);
    }

    @Override
    public boolean isDestroyed() {
        return CryptoUtils.allZero(keyMaterial);
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public int hashCode() {
        if (this.isDestroyed()) { throw new IllegalStateException("destroyed"); }
        return hashCode;
    }

    @Override
    public boolean equals(Object other) {
        if (this.isDestroyed()) { throw new IllegalStateException("destroyed"); }
        if (this == other) { return true; }
        if (other instanceof DestroyableSecretKey that) {
            return this.algorithm.equalsIgnoreCase(that.algorithm) &&
                    MessageDigest.isEqual(this.keyMaterial, that.keyMaterial);
        } else if (other instanceof SecretKey that) {
            return this.algorithm.equalsIgnoreCase(that.getAlgorithm()) &&
                    "RAW".equals(that.getFormat()) &&
                    MessageDigest.isEqual(this.keyMaterial, that.getEncoded());
        }
        return false;
    }

    public byte[] keyMaterial() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key material has been destroyed");
        }
        return keyMaterial;
    }

    @Override
    public String toString() {
        return "DestroyableSecretKey{destroyed=" + isDestroyed() + ", algorithm=" + algorithm + '}';
    }

    // Prevent serialization - these are intended as in-memory keys only
    @Serial
    private void writeObject(ObjectOutputStream out) throws InvalidClassException {
        throw new InvalidClassException("not serializable");
    }

    @Serial
    private void readObject(ObjectInputStream out) throws InvalidClassException {
        throw new InvalidClassException("not serializable");
    }
}
