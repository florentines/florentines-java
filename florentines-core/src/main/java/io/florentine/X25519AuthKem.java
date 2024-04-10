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

import static io.florentine.CryptoUtils.concat;
import static io.florentine.CryptoUtils.isX25519Key;
import static io.florentine.CryptoUtils.serialize;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class X25519AuthKem implements AuthKem {
    private static final Logger logger = LoggerFactory.getLogger(X25519AuthKem.class);

    private final CryptoSuite cryptoSuite;
    private final KeyWrapCipher keyWrapCipher;

    X25519AuthKem(CryptoSuite cryptoSuite) {
        this.cryptoSuite = requireNonNull(cryptoSuite);
        this.keyWrapCipher = cryptoSuite.dem().asKeyWrapCipher();
    }

    @Override
    public KeyPair generateKeyPair() {
        logger.trace("Generating X25519 keypair");
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("X25519");
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    @Override
    public KemState begin(KeyPair myKeys, Collection<PublicKey> theirKeys) {
        logger.trace("Beginning KEM state: localKeys={}, remoteKeys={}", myKeys, theirKeys);
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
        return new X25519KemState(myKeys, ephemeralKeys, theirKeys, cryptoSuite.identifier().getBytes(UTF_8));
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
                logger.debug("Generating DEK");
                messageKey = cryptoSuite.dem().importKey(CryptoUtils.randomBytes(32));
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
            var encapsulation = new ByteArrayOutputStream();
            try (var out = new DataOutputStream(encapsulation)) {
                out.write(serialize(ephemeralKeys.getPublic())); // 32 bytes
                out.write(keyId(localKeys.getPublic())); // 4 bytes
                out.writeShort(remoteKeys.size()); // 2 bytes

                for (var recipient : remoteKeys) {
                    out.write(keyId(recipient)); // 4 bytes
                    var kdfContext = kdfContext(recipient);

                    var es = CryptoUtils.x25519(ephemeralKeys.getPrivate(), recipient);
                    var ss = CryptoUtils.x25519(localKeys.getPrivate(), recipient);

                    try (var prk = HKDF.extract(salt, concat(es, ss));
                         var kek = HKDF.expandToKey(prk, kdfContext, 32, keyWrapCipher.algorithm())) {
                        var wrapped = keyWrapCipher.wrap(kek, dek, context);
                        out.write(wrapped); // 48 bytes
                    } finally {
                        CryptoUtils.wipe(es, ss);
                    }
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            var replySalt = replySalt(context, dek);
            var replyState = new X25519KemState(ephemeralKeys, generateKeyPair(), remoteKeys, replySalt);
            dek.destroy();
            return new KeyEncapsulation(replyState, encapsulation.toByteArray());
        }

        byte[] replySalt(byte[] context, DestroyableSecretKey dek) {
            return HKDF.expand(
                    HKDF.extract(("Florentine-Reply-Salt-" + cryptoSuite.identifier()).getBytes(UTF_8), dek.keyMaterial()),
                    context, 32);
        }

        private byte[] kdfContext(PublicKey recipient) {
            // This can be optimised by pre-allocating a fixed-size array to hold the keys and
            // pre-filling the first two entries. KISS for now.
            return concat(serialize(localKeys.getPublic()), serialize(ephemeralKeys.getPublic()), serialize(recipient));
        }

        private byte[] keyId(PublicKey pk) {
            var salt = serialize(ephemeralKeys.getPublic());
            return Arrays.copyOf(HKDF.extract(salt, serialize(pk)).getEncoded(), 4);
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
