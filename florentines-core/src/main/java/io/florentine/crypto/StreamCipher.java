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

import io.florentine.DestroyableSecretKey;

public interface StreamCipher {
    DataEncryptionKey importKey(byte[] keyMaterial, int offset);
    CipherState begin(DataEncryptionKey key, byte[] nonce);
    int getKeyLengthBytes();
    int getNonceLengthBytes();

    interface CipherState {
        CipherState encipher(byte[] plaintext, int offset, int length);
        default CipherState encipher(byte[] plaintext) {
            return encipher(plaintext, 0, plaintext.length);
        }

        default CipherState decipher(byte[] ciphertext, int offset, int length) {
            return encipher(ciphertext, offset, length);
        }

        default CipherState decipher(byte[] ciphertext) {
            return decipher(ciphertext, 0, ciphertext.length);
        }
    }

    final class DataEncryptionKey extends DestroyableSecretKey {
        DataEncryptionKey(byte[] keyMaterial, int offset, int length, String algorithm) {
            super(keyMaterial, offset, length, algorithm);
        }

        DataEncryptionKey(byte[] keyMaterial, String algorithm) {
            super(keyMaterial, algorithm);
        }
    }
}
