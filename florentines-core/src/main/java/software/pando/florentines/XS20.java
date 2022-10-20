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

final class XS20 implements StreamCipher {
    @Override
    public void process(SecretKey key, byte[] nonce, byte[] plaintext) {
        try (var cipher = Subtle.streamXSalsa20(key, nonce)) {
            cipher.process(ByteSlice.of(plaintext));
        }
    }
}
