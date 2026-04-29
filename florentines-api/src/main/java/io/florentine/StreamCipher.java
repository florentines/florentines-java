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

final class StreamCipher {
    static final StreamCipher AES128CTR = new StreamCipher("AES/CTR/NoPadding", 16, IvParameterSpec::new);
    static final StreamCipher AES256CTR = new StreamCipher("AES/CTR/NoPadding", 32, IvParameterSpec::new);
    static final StreamCipher CHACHA20 = new StreamCipher("ChaCha20", 32,
            nonce -> new ChaCha20ParameterSpec(Arrays.copyOf(nonce, 12), 0));

    private final ThreadLocal<Cipher> cipher;
    private final String algorithm;
    private final int keyLenBytes;
    private final Function<byte[], AlgorithmParameterSpec> ivMaker;

    StreamCipher(String algorithm, int keyLenBytes, Function<byte[], AlgorithmParameterSpec> ivMaker) {
        this.algorithm = Require.notBlank(algorithm, "algorithm");
        this.keyLenBytes = keyLenBytes;
        this.ivMaker = ivMaker;
        this.cipher = ThreadLocal.withInitial(() -> {
            try {
                return Cipher.getInstance(algorithm);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new UnsupportedOperationException(e);
            }
        });
        cipher.get(); // check algorithm is known
    }

    public int getKeyLenBytes() {
        return keyLenBytes;
    }

    CipherKey importKey(byte[] keyMaterial, int offset) {
        return new CipherKey(keyMaterial, offset, keyLenBytes, algorithm.split("/")[0]);
    }

    CipherState begin(CipherKey key, byte[] nonce) {
        if (nonce.length != 16) {
            throw new IllegalArgumentException("nonce must be 16 bytes exactly");
        }
        var cipher = this.cipher.get();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, ivMaker.apply(nonce));
            return new CipherState(cipher);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static final class CipherKey extends DestroyableSecretKey {
        CipherKey(byte[] keyMaterial, int offset, int length, String algorithm) {
            super(keyMaterial, offset, length, algorithm);
        }

        CipherKey(byte[] keyMaterial, String algorithm) {
            super(keyMaterial, algorithm);
        }
    }

    static final class CipherState {
        private final Cipher cipher;

        CipherState(Cipher cipher) {
            this.cipher = cipher;
        }

        CipherState encipher(byte[] plaintext, int offset, int length) {
            try {
                cipher.update(plaintext, offset, length, plaintext, offset);
            } catch (ShortBufferException e) {
                throw new AssertionError("stream cipher is not length-preserving??!");
            }
            return this;
        }

        CipherState encipher(byte[] plaintext) {
            return encipher(plaintext, 0, plaintext.length);
        }

        // For a stream cipher, enciphering and deciphering are the same operation, but it reads better
        // to have both methods.

        CipherState decipher(byte[] ciphertext, int offset, int length) {
            return encipher(ciphertext, offset, length);
        }

        CipherState decipher(byte[] ciphertext) {
            return decipher(ciphertext, 0, ciphertext.length);
        }
    }
}
