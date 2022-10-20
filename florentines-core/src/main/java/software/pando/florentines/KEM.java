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

import static java.util.Objects.requireNonNull;

import java.security.KeyPair;
import java.util.Collection;

import javax.crypto.SecretKey;

interface KEM {
    KEM AUTHKEM_X25519 = new X25519AuthKem();

    KeyPair generateKeyPair();

    String getIdentifier();

    EncapsulatedKey encapsulate(KeyInfo sender, Collection<KeyInfo> recipients, byte[] assocData);

    final class EncapsulatedKey {
        final SecretKey key;
        final byte[] encapsulation;

        EncapsulatedKey(SecretKey dataKey, byte[] encapsulation) {
            this.key = requireNonNull(dataKey);
            this.encapsulation = requireNonNull(encapsulation);
        }

        public byte[] getEncapsulation() {
            return encapsulation.clone();
        }
    }

}
