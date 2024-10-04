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

import static io.florentine.Utils.threadLocal;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;

final class ChaCha20 implements StreamCipher {
    private static final ThreadLocal<Cipher> CIPHER_THREAD_LOCAL = threadLocal(() -> Cipher.getInstance("ChaCha20"));

    @Override
    public String identifier() {
        return "CC20";
    }

    @Override
    public int nonceSizeBytes() {
        return 12;
    }

    @Override
    public byte[] process(byte[] keyBytes, byte[] nonce, byte[] content) {
        var cipher = CIPHER_THREAD_LOCAL.get();
        try (var key = new DestroyableSecretKey(keyBytes, cipher.getAlgorithm())) {
            cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
            cipher.doFinal(content, 0, content.length, content);
            return content;
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return identifier();
    }
}
