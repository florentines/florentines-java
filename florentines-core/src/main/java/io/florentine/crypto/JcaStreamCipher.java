/*
 * Copyright 2025-2026 Neil Madden.
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

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.function.Function;

public class JcaStreamCipher implements StreamCipher {
    public static final JcaStreamCipher A128CTR = new JcaStreamCipher("AES/CTR/NoPadding", 16, 16);
    public static final JcaStreamCipher CC20 = new JcaStreamCipher("ChaCha20", 32, 12,
            nonce -> new ChaCha20ParameterSpec(Arrays.copyOf(nonce, 12), 0));

    private final ThreadLocal<Cipher> cipherThreadLocal;
    private final String keyAlg;
    private final int keyLen;
    private final Function<byte[], AlgorithmParameterSpec> ivConstructor;
    private final int nonceLen;

    JcaStreamCipher(String cipherAlgorithm, int keyLenBytes, int nonceLenBytes,
                    Function<byte[], AlgorithmParameterSpec> ivConstructor) {
        cipherThreadLocal = ThreadLocal.withInitial(() -> {
            try {
                return Cipher.getInstance(cipherAlgorithm);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new UnsupportedOperationException(e);
            }
        });
        keyAlg = cipherAlgorithm.split("/")[0];
        keyLen = keyLenBytes;
        nonceLen = nonceLenBytes;
        this.ivConstructor = ivConstructor;
    }

    JcaStreamCipher(String cipherAlgorithm, int keyLenBytes, int nonceLenBytes) {
        this(cipherAlgorithm, keyLenBytes, nonceLenBytes, IvParameterSpec::new);
    }

    @Override
    public int getKeyLengthBytes() {
        return keyLen;
    }

    @Override
    public int getNonceLengthBytes() {
        return nonceLen;
    }

    @Override
    public DataEncryptionKey importKey(byte[] keyMaterial, int offset) {
        return new DataEncryptionKey(keyMaterial, offset, keyLen, keyAlg);
    }

    @Override
    public CipherState begin(DataEncryptionKey key, byte[] nonce) {
        try {
            var cipher = cipherThreadLocal.get();
            cipher.init(Cipher.DECRYPT_MODE, key, iv(nonce));
            return new State(cipher);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
    }

    final AlgorithmParameterSpec iv(byte[] nonce) {
        return ivConstructor.apply(nonce);
    }

    private record State(Cipher cipher) implements CipherState {
        @Override
        public CipherState encipher(byte[] plaintext, int offset, int length) {
            try {
                int bytesEncrypted = cipher.update(plaintext, offset, length, plaintext);
                assert bytesEncrypted == length;
            } catch (ShortBufferException e) {
                throw new AssertionError(e);
            }
            return this;
        }
    }
}
