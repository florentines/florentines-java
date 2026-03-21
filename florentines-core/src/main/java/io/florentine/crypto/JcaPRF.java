/*
 * Copyright 2025 Neil Madden.
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

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public final class JcaPRF implements PseudoRandomFunction {
    public static final JcaPRF HS256 = new JcaPRF("HmacSHA256", 16);
    public static final JcaPRF HS512 = new JcaPRF("HmacSHA512", 32);

    private final ThreadLocal<Mac> macThreadLocal;
    private final String macAlgorithm;
    private final int keyLen;

    JcaPRF(String macAlgorithm, int keyLen) {
        this.macAlgorithm = macAlgorithm;
        this.keyLen = keyLen;
        this.macThreadLocal = ThreadLocal.withInitial(() -> {
            try {
                return Mac.getInstance(macAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new UnsupportedOperationException(e);
            }
        });
    }

    @Override
    public int getKeyLengthBytes() {
        return keyLen;
    }

    @Override
    public int getTagLengthBytes() {
        return macThreadLocal.get().getMacLength();
    }

    @Override
    public io.florentine.DestroyableSecretKey importKey(byte[] keyMaterial, int offset) {
        Objects.checkFromIndexSize(offset, keyLen, keyMaterial.length);
        return new io.florentine.DestroyableSecretKey(keyMaterial, offset, offset + keyLen, macAlgorithm);
    }

    @Override
    public byte[] process(io.florentine.DestroyableSecretKey key, byte[] data) {
        var mac = macThreadLocal.get();
        try {
            mac.init(key);
            return mac.doFinal(data);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
