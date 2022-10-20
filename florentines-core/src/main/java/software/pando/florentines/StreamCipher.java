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

/**
 * Represents an IND-CPA secure stream cipher.
 */
interface StreamCipher {
    /**
     * The XSalsa20 stream cipher.
     */
    StreamCipher XS20 = new XS20();

    /**
     * Processes (encrypts or decrypts) the given data with the stream cipher using the supplied key and nonce. The
     * data is encrypted or decrypted in-place, overwriting the original data.
     *
     * @param key the secret key.
     * @param nonce the nonce.
     * @param data the data to encrypt or decrypt.
     */
    void process(SecretKey key, byte[] nonce, byte[] data);
}
