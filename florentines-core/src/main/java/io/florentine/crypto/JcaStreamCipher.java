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

import io.florentine.dem.DataKey;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

abstract class JcaStreamCipher implements StreamCipher {
    private final Cipher cipher;
    private final String keyAlg;

    JcaStreamCipher(String cipherAlgorithm) {
        try {
            cipher = Cipher.getInstance(cipherAlgorithm);
            keyAlg = cipherAlgorithm.split("/")[0];
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    @Override
    public DataKey importKey(byte[] keyMaterial, int offset, int len) {
        return new DataKey(keyMaterial, offset, offset+len, keyAlg);
    }

    @Override
    public StreamCipher init(DataKey key, byte[] nonce) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, iv(nonce));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
        return this;
    }

    AlgorithmParameterSpec iv(byte[] nonce) {
        return new IvParameterSpec(nonce);
    }

    @Override
    public StreamCipher encipher(byte[] plaintext, int offset, int length) {
        try {
            int bytesEncrypted = cipher.update(plaintext, offset, length, plaintext);
            assert bytesEncrypted == length;
        } catch (ShortBufferException e) {
            throw new AssertionError(e);
        }
        return this;
    }

}
