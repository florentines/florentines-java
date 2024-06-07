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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;

final class ChaCha20Cipher implements StreamCipher {

    private static final ThreadLocal<Cipher> CIPHER_THREAD_LOCAL = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance("ChaCha20");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        }
    });

    @Override
    public String algorithm() {
        return "ChaCha20";
    }

    @Override
    public String identifier() {
        return "CC20";
    }

    @Override
    public int nonceSizeBytes() {
        return 12;
    }

    @Override
    public void cipher(SecretKey key, byte[] nonce, byte[] data) {
        if (nonce.length != nonceSizeBytes()) {
            nonce = Arrays.copyOf(nonce, nonceSizeBytes());
        }
        try {
            var cipher = CIPHER_THREAD_LOCAL.get();
            cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
            cipher.doFinal(data, 0, data.length, data);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (GeneralSecurityException | RuntimeException e) {
            CIPHER_THREAD_LOCAL.remove();
            throw new RuntimeException(e);
        }
    }
}
