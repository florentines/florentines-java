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

import static java.nio.charset.StandardCharsets.*;
import static java.util.Objects.requireNonNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

final class X25519AuthKem implements AuthKem {
    private final String cryptoSuiteIdentifier;
    private final String dataKeyAlgorithm;

    @Override
    public KeyPair generateKeyPair() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("X25519");
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    X25519AuthKem(String cryptoSuiteIdentifier, String dataKeyAlgorithm) {
        this.cryptoSuiteIdentifier = cryptoSuiteIdentifier;
        this.dataKeyAlgorithm = dataKeyAlgorithm;
    }

    @Override
    public KemState begin(KeyPair myKeys, Collection<PublicKey> theirKeys) {
        requireNonNull(myKeys, "Local party key-pair");
        requireNonNull(theirKeys, "Remote party public keys");

        var ephemeralKeys = generateKeyPair();
        return new X25519KemState(myKeys, ephemeralKeys, theirKeys, cryptoSuiteIdentifier.getBytes(UTF_8));
    }

    private final class X25519KemState implements KemState {

        private final KeyPair localKeys;
        private final KeyPair ephemeralKeys;
        private final Collection<PublicKey> remoteKeys;
        private final byte[] salt;

        private DestroyableSecretKey messageKey;

        private X25519KemState(KeyPair localKeys, KeyPair ephemeralKeys, Collection<PublicKey> remoteKeys, byte[] salt) {
            this.localKeys = localKeys;
            this.ephemeralKeys = ephemeralKeys;
            this.remoteKeys = remoteKeys;
            this.salt = salt;
        }

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
        public void destroy() {
            CryptoUtils.destroy(messageKey, ephemeralKeys.getPrivate());
        }

        @Override
        public boolean isDestroyed() {
            return messageKey.isDestroyed() || ephemeralKeys.getPrivate().isDestroyed();
        }
    }
}
