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

import io.florentine.crypto.DestroyableSecretKey;

import static io.florentine.Utils.threadLocal;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.ChaCha20ParameterSpec;

final class ChaCha20 implements StreamCipher {
    private static final ThreadLocal<Cipher> CIPHER_THREAD_LOCAL = threadLocal(() -> Cipher.getInstance("ChaCha20"));

    private DestroyableSecretKey key;
    private byte[] nonce;
    private int blockCounter;
    private boolean valid = false;

    ChaCha20() {
        // Default constructor, should only be called once
    }

    private ChaCha20(byte[] key, byte[] nonce) {
        this.key = new DestroyableSecretKey(key, "ChaCha20");
        this.nonce = nonce;
        this.valid = true;
        this.blockCounter = 0;
    }

    @Override
    public StreamCipher init(byte[] key, byte[] nonce) {
        return new ChaCha20(key, nonce);
    }

    @Override
    public byte[] process(byte[] data) {
        if (!valid) { throw new IllegalStateException(); }
        var cipher = CIPHER_THREAD_LOCAL.get();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, blockCounter));
            cipher.update(data, 0, data.length, data);
            blockCounter = Math.addExact(blockCounter, numBlocks(data.length));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException e) {
            throw new AssertionError(e);
        }
        return data;
    }

    private static int numBlocks(int numBytes) {
        return (numBytes + 63) / 64;
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
    public void close() {
        Utils.destroy(key);
        Utils.wipe(nonce);
        valid = false;
    }

    @Override
    public String toString() {
        return identifier();
    }
}
