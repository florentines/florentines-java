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

package io.florentine;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Implementations of <a href="https://datatracker.ietf.org/doc/html/rfc2104">Hash-based Message Authentication Code</a>
 * (HMAC). Many security details of Florentines rely specifically on security properties of HMAC rather than a more
 * generic notion such as a pseudorandom function, so we reference HMAC specifically by name. For example, the derivation
 * of encryption keys uses HKDF-Extract, which relies on HMAC behaving as a Dual-PRF. Future security analysis could
 * relax this requirement.
 */
final class HMAC {
    static final HMAC HS256 = new HMAC("HmacSHA256", 16);
    static final HMAC HS512 = new HMAC("HmacSHA512", 32);

    private final ThreadLocal<Mac> mac;
    private final String algorithm;
    private final int keyLenBytes;
    private final int tagLenBytes;

    HMAC(String algorithm, int keyLenBytes) {
        this.algorithm = Require.notBlank(algorithm, "algorithm");
        this.keyLenBytes = keyLenBytes;
        this.mac = ThreadLocal.withInitial(() -> {
            try {
                return Mac.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new AssertionError("unsupported algorithm", e);
            }
        });
        this.tagLenBytes = mac.get().getMacLength();
    }

    public int getKeyLenBytes() {
        return keyLenBytes;
    }

    public int getTagLenBytes() {
        return tagLenBytes;
    }

    HmacKey importKey(byte[] keyMaterial, int offset) {
        return new HmacKey(keyMaterial, offset, keyLenBytes, algorithm);
    }

    byte[] compute(HmacKey key, byte[] data) {
        var hmac = mac.get();
        try {
            hmac.init(key);
            return hmac.doFinal(data);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    void verify(HmacKey key, byte[] data, byte[] tag) {
        var computed = compute(key, data);
        if (!MessageDigest.isEqual(tag, computed)) {
            throw new IllegalArgumentException("invalid HMAC tag");
        }
    }

    byte[] extractIndependentKey(byte[] salt, byte[] inputKeyMaterial) {
        try (var key = importKey(salt, 0)) {
            return compute(key, inputKeyMaterial);
        }
    }

    byte[] cascade(HmacKey key, Iterable<byte[]> data) {
        byte[] tag = null;
        for (var datum : data) {
            tag = compute(key, datum);
            // Overwrite the existing key material in-place for efficiency and security
            System.arraycopy(tag, 0, key.keyMaterial, 0, keyLenBytes);
        }
        key.destroy();
        if (tag == null) {
            throw new IllegalArgumentException("no data supplied");
        }
        return tag;
    }

    static final class HmacKey extends DestroyableSecretKey {
        HmacKey(byte[] keyMaterial, int offset, int length, String algorithm) {
            super(keyMaterial, offset, length, algorithm);
        }

        HmacKey(byte[] keyMaterial, String algorithm) {
            super(keyMaterial, algorithm);
        }
    }
}
