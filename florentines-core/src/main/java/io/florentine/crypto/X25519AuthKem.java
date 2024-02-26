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

import static io.florentine.crypto.CryptoUtils.concat;
import static io.florentine.crypto.CryptoUtils.isX25519Key;
import static io.florentine.crypto.CryptoUtils.serialize;
import static java.nio.charset.StandardCharsets.*;
import static java.util.Objects.requireNonNull;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Optional;

final class X25519AuthKem implements AuthKem {
    private final String cryptoSuiteIdentifier;
    private final String dataKeyAlgorithm;
    private final KeyWrapCipher keyWrapCipher;

    @Override
    public KeyPair generateKeyPair() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("X25519");
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    X25519AuthKem(String cryptoSuiteIdentifier, String dataKeyAlgorithm, KeyWrapCipher keyWrapCipher) {
        this.cryptoSuiteIdentifier = cryptoSuiteIdentifier;
        this.dataKeyAlgorithm = dataKeyAlgorithm;
        this.keyWrapCipher = keyWrapCipher;
    }

    @Override
    public KemState begin(KeyPair myKeys, Collection<PublicKey> theirKeys) {
        requireNonNull(myKeys, "Local party key-pair");
        requireNonNull(theirKeys, "Remote party public keys");
        requireNonNull(myKeys.getPrivate(), "Local private key");
        requireNonNull(myKeys.getPublic(), "Local public key");

        if (!isX25519Key(myKeys.getPrivate()) || !isX25519Key(myKeys.getPublic())) {
            throw new IllegalArgumentException("Local keys are not X25519 keys");
        }
        if (theirKeys.stream().anyMatch(key -> !isX25519Key(key))) {
            throw new IllegalArgumentException("One of the remote keys is not for X25519");
        }

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
        public KeyEncapsulation encapsulate(byte[] context) {
            if (isDestroyed()) {
                throw new IllegalStateException("destroyed");
            }
            if (localKeys.getPrivate() == null) {
                throw new IllegalStateException("no local private key");
            }

            var dek = key();
            var baos = new ByteArrayOutputStream();
            try (var out = new DataOutputStream(baos)) {
                out.writeShort(remoteKeys.size());
                out.write(serialize(localKeys.getPublic()));

                for (var recipient : remoteKeys) {
                    var es = CryptoUtils.x25519(ephemeralKeys.getPrivate(), recipient);
                    var ss = CryptoUtils.x25519(localKeys.getPrivate(), recipient);

                    var kdfContext = kdfContext(recipient);

                    try (var prk = HKDF.extract(salt, concat(es, ss));
                         var kek = new DestroyableSecretKey(HKDF.expand(prk, kdfContext, 32), keyWrapCipher.algorithm())) {
                        var wrapped = keyWrapCipher.wrap(kek, dek, context);
                        out.write(wrapped);
                    } finally {
                        CryptoUtils.wipe(es);
                        CryptoUtils.wipe(ss);
                    }
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            return null;
        }

        private byte[] kdfContext(PublicKey recipient) {
            return concat(serialize(localKeys.getPublic()), serialize(ephemeralKeys.getPublic()), serialize(recipient));

        }

        @Override
        public Optional<KeyDecapsulation> decapsulate(byte[] encapsulatedKey, byte[] context) {
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
