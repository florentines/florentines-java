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

package io.florentine.crypto;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import javax.security.auth.DestroyFailedException;

final class X25519AuthKem implements AuthKem {
    private final String dataKeyAlgorithm;

    X25519AuthKem(String dataKeyAlgorithm) {
        this.dataKeyAlgorithm = dataKeyAlgorithm;
    }

    @Override
    public KemState begin(KeyPair myKeys, Collection<? extends PublicKey> theirKeys) {
        return null;
    }

    private final class X25519KemState implements KemState {

        private final KeyPair localKeys;
        private final KeyPair emphemeralKeys;
        private final Collection<PublicKey> remoteKeys;

        private DestroyableSecretKey messageKey;

        @Override
        public DestroyableSecretKey key() {
            if (messageKey == null) {
                messageKey = new DestroyableSecretKey(CryptoUtils.randomBytes(32), dataKeyAlgorithm);
            }
            return messageKey;
        }

        @Override
        public KeyEncapsulation encapsulate(List<byte[]> context) {
            return null;
        }

        @Override
        public Optional<KeyDecapsulation> decapsulate(byte[] encapsulatedKey, List<byte[]> context) {
            return Optional.empty();
        }

        @Override
        public void destroy() throws DestroyFailedException {
            KemState.super.destroy();
        }

        @Override
        public boolean isDestroyed() {
            return KemState.super.isDestroyed();
        }
    }
}
