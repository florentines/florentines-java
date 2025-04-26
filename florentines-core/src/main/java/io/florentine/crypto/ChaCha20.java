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

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

final class ChaCha20 implements StreamCipher {
    private final Cipher cipher;
    private final DestroyableSecretKey key;
    private byte[] nonce;

    ChaCha20(DestroyableSecretKey key, byte[] nonce) {
        try {
            var cipher = Cipher.getInstance("ChaCha20");
            if (key != null) {
                cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
            }

            this.cipher = cipher;
            this.key = key;
            this.nonce = nonce;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            throw new AssertionError(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public StreamCipher key(DestroyableSecretKey key) {
        return new ChaCha20(key, nonce);
    }

    @Override
    public StreamCipher nonce(byte[] nonce) {
        checkState();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
        return this;
    }

    @Override
    public StreamCipher process(byte[] data) {
        checkState();
        try {
            cipher.update(data, 0, data.length, data);
        } catch (ShortBufferException e) {
            throw new AssertionError(e);
        }
        return this;
    }

    @Override
    public void close() {
        key.destroy();
    }

    private void checkState() {
        if (key != null && key.isDestroyed()) {
            throw new IllegalStateException("Key material has been destroyed");
        }
    }
}
