/*
 * Copyright 2022 Neil Madden.
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

package software.pando.florentines;

import javax.crypto.SecretKey;

import software.pando.crypto.nacl.ByteSlice;
import software.pando.crypto.nacl.Subtle;

/**
 * A length-preserving stream cipher that provides semantic security against chosen plaintext attacks (IND-CPA).
 */
interface StreamCipher {

    /**
     * The XSalsa20 stream cipher.
     */
    StreamCipher XS20 = new StreamCipher() {
        @Override
        public SecretKey key(byte[] keyMaterial, int offset, int length) {
            return Subtle.streamXSalsa20Key(ByteSlice.of(keyMaterial, offset, length));
        }

        @Override
        public void process(SecretKey key, byte[] nonce, byte[]... payloads) {
            try (var cipher = Subtle.streamXSalsa20(key, nonce)) {
                for (byte[] payload : payloads) {
                    cipher.process(ByteSlice.of(payload));
                }
            }
        }
    };

    /**
     * Imports the given key material as a secret key for the stream cipher.
     *
     * @param keyMaterial the key material to use for the stream cipher. This should not be used for any other
     *                    purpose and should be zeroed out after calling this method.
     * @param offset the offset at which the key material starts in the byte array.
     * @param length the length of the key material, which should be at least 16 bytes for most algorithms.
     * @return the imported secret key.
     */
    SecretKey key(byte[] keyMaterial, int offset, int length);

    /**
     * Imports the given key material as a secret key for the stream cipher.
     *
     * @param keyMaterial the key material to use for the stream cipher. This should not be used for any other
     *                    purpose and should be zeroed out after calling this method.
     * @return the imported secret key.
     */
    default SecretKey key(byte[] keyMaterial) {
        return key(keyMaterial, 0, keyMaterial.length);
    }

    /**
     * Processes the given payload blocks with the stream cipher, encrypting or decrypting them in-place. The payloads
     * are processed as if they were concatenated into a single contiguous region.
     *
     * @param key the key.
     * @param nonce the nonce.
     * @param payloads the payloads to encrypt in-place.
     */
    void process(SecretKey key, byte[] nonce, byte[]... payloads);
}
