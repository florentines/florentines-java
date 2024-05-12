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
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

import org.msgpack.core.MessagePack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class X25519AuthKem implements AuthKem {
    private static final Logger logger = LoggerFactory.getLogger(X25519AuthKem.class);

    private final CryptoSuite cryptoSuite;
    private final KeyWrapCipher keyWrapCipher;

    X25519AuthKem(CryptoSuite cryptoSuite) {
        this.cryptoSuite = requireNonNull(cryptoSuite, "cryptoSuite");
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
    public KemState begin(String applicationLabel, LocalParty localParty, Collection<RemoteParty> remoteParties) {
        logger.trace("Beginning KEM state: label={}, localKeys={}, remoteKeys={}", applicationLabel, localParty,
                remoteParties);
        requireNonNull(applicationLabel, "Application label");
        requireNonNull(localParty, "Local party key-pair");
        requireNonNull(remoteParties, "Remote party public keys");
        requireNonNull(localParty.staticKeys().getPrivate(), "Local private key");
        requireNonNull(localParty.staticKeys().getPublic(), "Local public key");

        if (!isX25519Key(localParty.staticKeys().getPrivate()) || !isX25519Key(localParty.staticKeys().getPublic())) {
            throw new IllegalArgumentException("Local keys are not X25519 keys");
        }
        if (remoteParties.stream()
                .anyMatch(party -> !isX25519Key(party.getPublicKeyForAlgorithm(cryptoSuite).orElseThrow()))) {
            throw new IllegalArgumentException("One of the remote keys is not for X25519");
        }

        var ephemeralKeys = generateKeyPair();
        return new X25519KemState(applicationLabel, localParty, ephemeralKeys, remoteParties,
                cryptoSuite.identifier().getBytes(UTF_8));
    }

    private final class X25519KemState implements KemState {

        private final String applicationLabel;
        private final LocalParty localParty;
        private final KeyPair ephemeralKeys;
        private final Collection<? extends RemoteParty> remoteParties;
        private final byte[] salt;

        private DestroyableSecretKey messageKey;

        private X25519KemState(String applicationLabel, LocalParty localParty, KeyPair ephemeralKeys,
                               Collection<? extends RemoteParty> remoteParties,
                               byte[] salt) {
            this.applicationLabel = applicationLabel;
            this.localParty = localParty;
            this.ephemeralKeys = ephemeralKeys;
            this.remoteParties = remoteParties;
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
            if (localParty.staticKeys().getPrivate() == null) {
                throw new IllegalStateException("no local private key");
            }

            var encapsulation = new ByteArrayOutputStream();
            try (var out = new DataOutputStream(encapsulation);
                 var dek = key()) {
                out.write(serialize(ephemeralKeys.getPublic())); // 32 bytes
                out.write(keyId(localParty.staticKeys().getPublic())); // 4 bytes
                out.writeShort(remoteParties.size()); // 2 bytes

                for (var recipient : remoteParties) {
                    var recipientPk = recipient.getPublicKeyForAlgorithm(cryptoSuite).orElseThrow();
                    out.write(keyId(recipientPk)); // 4 bytes
                    var kdfContext = kdfContext(recipient, recipientPk);

                    var es = CryptoUtils.x25519(ephemeralKeys.getPrivate(), recipientPk);
                    var ss = CryptoUtils.x25519(localParty.staticKeys().getPrivate(), recipientPk);

                    try (var prk = HKDF.extract(salt, concat(es, ss));
                         var kek = HKDF.expandToKey(prk, kdfContext, 32, keyWrapCipher.algorithm())) {
                        var wrapped = keyWrapCipher.wrap(kek, dek, context);
                        out.write(wrapped); // 48 bytes
                    } finally {
                        CryptoUtils.wipe(es, ss);
                    }
                }

                var replySalt = replySalt(context, dek);
                var ephemeralParty = new InMemoryLocalParty(cryptoSuite, localParty.partyInfo(), ephemeralKeys);
                var replyState = new X25519KemState(applicationLabel, ephemeralParty, generateKeyPair(), remoteParties,
                        replySalt);
                return new KeyEncapsulation(replyState, encapsulation.toByteArray());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        byte[] replySalt(byte[] context, DestroyableSecretKey dek) {
            return HKDF.expand(
                    HKDF.extract(("Florentine-Reply-Salt-" + cryptoSuite.identifier()).getBytes(UTF_8), dek.keyMaterial()),
                    context, 32);
        }

        private byte[] kdfContext(RemoteParty recipient, PublicKey recipientPk) {
            // TODO: this can be significantly optimised, e.g. by reusing buffers and pre-filling fields that are the
            //  same for all recipients.
            var baos = new ByteArrayOutputStream();
            try (var out = MessagePack.newDefaultPacker(baos)) {

                // Florentines use the recommendations in NIST SP800-56C (rev 2), section 5.1, which recommends the
                // FixedInfo have the following fields:
                // 1. An application-specific *label*
                // 2. Any relevant *context* fields
                // 3. An encoding of the length of the derived key material to be produced (in bits).

                // 1. Label:
                out.packString(applicationLabel);

                // 2. Context:
                // We follow the concatenation format for fixedInfo specified in NIST SP.800-56Ar3 section 5.8.2.1.1:

                // AlgorithmID
                out.packString("Florentine-" + cryptoSuite.identifier());

                // PartyUInfo
                var partyUInfo = localParty.partyInfo();
                out.packBinaryHeader(partyUInfo.length);
                out.writePayload(partyUInfo);

                var partyUPk = serialize(localParty.staticKeys().getPublic());
                out.packBinaryHeader(partyUPk.length);
                out.addPayload(partyUPk);
                var epk = serialize(ephemeralKeys.getPublic());
                out.packBinaryHeader(epk.length);
                out.addPayload(epk);

                // PartyVInfo
                var partyVInfo = recipient.partyInfo();
                out.packBinaryHeader(partyVInfo.length);
                out.addPayload(partyVInfo);

                var partyVPk = serialize(recipientPk);
                out.packBinaryHeader(partyVPk.length);
                out.addPayload(partyVPk);

                // SuppPubInfo (unused)
                // SuppPrivInfo (unused)

                // 3. L - length of derived key material in bits. Always 256 for Florentines.
                out.packShort((short) 256);

            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            return baos.toByteArray();
        }

        private byte[] keyId(PublicKey pk) {
            var salt = serialize(ephemeralKeys.getPublic());
            try (var tmp = HKDF.extract(salt, serialize(pk))) {
                return Arrays.copyOf(tmp.getEncoded(), 4);
            }
        }

        @Override
        public Optional<KeyDecapsulation> decapsulate(byte[] encapsulatedKey, byte[] context) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int writeTo(OutputStream out) throws IOException {
            if (isDestroyed()) {
                throw new IllegalStateException("kem state has been destroyed");
            }
            throw new UnsupportedOperationException();
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
