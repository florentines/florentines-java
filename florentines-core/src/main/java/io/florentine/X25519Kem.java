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

import static io.florentine.Utils.emptyBytes;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.msgpack.value.ValueFactory.newBinary;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import javax.security.auth.Destroyable;

import org.msgpack.core.MessagePack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.pando.crypto.nacl.Bytes;
import software.pando.crypto.nacl.Crypto;
import software.pando.crypto.nacl.CryptoBox;
import software.pando.crypto.nacl.Subtle;

final class X25519Kem extends KEM {
    private static final Logger logger = LoggerFactory.getLogger(X25519Kem.class);

    private static final String IDENTIFIER_PREFIX = "Florentine-AuthKEM-X25519-";
    private static final String KEY_ID_SALT = IDENTIFIER_PREFIX + "KeyID-Salt";
    private static final String REPLY_SALT = IDENTIFIER_PREFIX + "Reply-Salt";

    @Override
    public String identifier() {
        return "AuthKEM-X25519";
    }

    @Override
    KeyPair generateKeyPair() {
        return freshKeyPair();
    }

    static KeyPair freshKeyPair() {
        return CryptoBox.keyPair();
    }

    @Override
    State begin(DEM dem, LocalIdentity local, Collection<PublicIdentity> remote) {
        requireNonNull(local, "local keys");
        Require.notEmpty(remote, "remote keys");
        Require.matches(X25519Kem::isX25519Key, local.secretKey(), "Local private key is not for X25519");
        Require.matches(X25519Kem::isX25519Key, local.publicKey(), "Local public key is not for X25519");
        Require.all(id -> isX25519Key(id.publicKey()), remote, "Remote public keys must all be X25519 keys");
        // NB we could also check that the local public key matches the private key, but this is expensive, and we
        // prevent known attacks by including all PKs in the KDF inputs.

        var initialSalt = IDENTIFIER_PREFIX + dem.identifier();
        return new State(dem, local, false, generateKeyPair(), List.copyOf(remote), initialSalt.getBytes(US_ASCII));
    }

    private static byte[] x25519(Key secretKey, PublicKey publicKey) {
        return Subtle.scalarMultiplication((PrivateKey) secretKey, publicKey);
    }

    private static final class State implements KEM.State {
        private volatile boolean destroyed = false;
        private final boolean localKeysAreEphemeral;
        private final LocalIdentity localKeys;
        private final KeyPair ephemeralKeys;
        private final List<PublicIdentity> remoteKeys;
        private final byte[] kdfSalt;
        private final DEM dem;
        private final DestroyableSecretKey demKey;
        private final byte[] keyIdSalt;

        private State(DEM dem, LocalIdentity localKeys, boolean localKeysAreEphemeral, KeyPair ephemeralKeys,
                      List<PublicIdentity> remoteKeys, byte[] salt) {
            this.localKeys = requireNonNull(localKeys, "localKeys");
            this.ephemeralKeys = requireNonNull(ephemeralKeys, "ephemeralKeys");
            this.remoteKeys = requireNonNull(remoteKeys, "remoteKeys");
            this.kdfSalt = requireNonNull(salt, "salt");
            this.dem = requireNonNull(dem, "dem");
            this.localKeysAreEphemeral = localKeysAreEphemeral;
            this.demKey = dem.generateKey();
            this.keyIdSalt = PRF.HS512.calculate(KEY_ID_SALT.getBytes(US_ASCII), serialize(ephemeralKeys.getPublic()));

            Require.between(remoteKeys.size(), 1, 65536, "# remote keys must be between 1 and 65,535");
        }

        @Override
        public DestroyableSecretKey key() {
            return demKey;
        }

        @Override
        public EncapsulatedKey encapsulate(byte[] context) {
            var epk = serialize(ephemeralKeys.getPublic());
            var kw = dem.asKeyWrapper();
            var baos = new ByteArrayOutputStream();
            try (var out = MessagePack.newDefaultPacker(baos)) {
                out.packValue(newBinary(epk));
                out.packValue(newBinary(keyId(keyIdSalt, localKeys.publicKey())));
                out.packShort((short) remoteKeys.size());

                for (var recipient : remoteKeys) {
                    out.packValue(newBinary(keyId(keyIdSalt, recipient.publicKey())));
                    var kdfContext = kdfContext(localKeys, recipient, ephemeralKeys.getPublic(),
                            context);
                    try (var wrapKey = keyAgreement(ephemeralKeys.getPrivate(), recipient.publicKey(),
                                                    localKeys.secretKey(), recipient.publicKey(), kdfContext)) {
                        var wrapped = kw.wrap(wrapKey, demKey);
                        out.packValue(newBinary(wrapped));
                    }
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            // The ephemeral keys become the new local keys for any replies
            var localIdentity = new LocalIdentity(
                    localKeys.identifier(),
                    ephemeralKeys.getPrivate(),
                    ephemeralKeys.getPublic());
            var replyState = new State(dem, localIdentity, true, freshKeyPair(), remoteKeys, replySalt(context));
            return new EncapsulatedKey(baos.toByteArray(), replyState);
        }

        @Override
        public Optional<DecapsulatedKey> decapsulate(byte[] encapsulatedKey, byte[] context) {
            try (var in = MessagePack.newDefaultUnpacker(new ByteArrayInputStream(encapsulatedKey))) {

                var epk = in.unpackValue().asBinaryValue().asByteArray();
                var ephemeralPk = deserialize(epk);
                var expectedKeyId = keyId(keyIdSalt, localKeys.publicKey());
                var remoteKid = in.unpackValue().asBinaryValue().asByteArray();

                var sender = remoteKeys.stream()
                        .filter(candidate -> Arrays.equals(remoteKid, keyId(keyIdSalt, candidate.publicKey())))
                        .findAny();
                if (sender.isEmpty()) {
                    return Optional.empty();
                }

                var numRecipients = in.unpackShort();
                for (int i = 0; i < numRecipients; ++i) {
                    var kid = in.unpackValue().asBinaryValue().asByteArray();
                    var wrappedKey = in.unpackValue().asBinaryValue().asByteArray();

                    if (Bytes.equal(expectedKeyId, kid)) {
                        // A candidate...
                        var kdfContext = kdfContext(sender.get(), localKeys, ephemeralPk, context);
                        try (var unwrapKey = keyAgreement(localKeys.secretKey(), ephemeralPk,
                                localKeys.secretKey(), sender.get().publicKey(), kdfContext)) {
                            var unwrappedKey = dem.asKeyWrapper().unwrap(unwrapKey, wrappedKey, dem.identifier());
                            if (unwrappedKey.isPresent()) {
                                var ephemeralIdentity = new PublicIdentity(sender.get().identifier(), ephemeralPk);
                                var replyState = new State(dem, localKeys, false, freshKeyPair(),
                                        List.of(ephemeralIdentity), replySalt(context));
                                return Optional.of(new DecapsulatedKey(unwrappedKey.get(), sender.get(), replyState));
                            }
                        }
                    }
                }

            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            return Optional.empty();
        }

        @Override
        public void destroy() {
            Utils.destroy(ephemeralKeys.getPrivate(), demKey);
            if (localKeysAreEphemeral && localKeys.secretKey() instanceof Destroyable sk) {
                Utils.destroy(sk);
            }
            destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }

        private DestroyableSecretKey keyAgreement(Key esPriv, PublicKey esPub, Key ssPriv, PublicKey ssPub,
                                                  byte[] context) {
            byte[] es = emptyBytes(), ss = emptyBytes(), secret = emptyBytes(), concatenated = emptyBytes();
            try {
                es = x25519(esPriv, esPub);
                ss = x25519(ssPriv, ssPub);
                concatenated = Utils.concat(es, ss);
                secret = Crypto.kdfDeriveFromInputKeyMaterial(kdfSalt, concatenated, context, 32);
                return new DestroyableSecretKey(secret, dem.identifier());
            } finally {
                Utils.wipe(secret, concatenated, es, ss);
            }
        }

        private byte[] kdfContext(Identity sender, Identity recipient, PublicKey epk, byte[] context) {
            try (var packer = MessagePack.newDefaultBufferPacker()) {
                packer.packValue(newBinary(context));
                packer.packValue(newBinary(serialize(epk)));
                packer.packValue(newBinary(serialize(sender.publicKey())));
                packer.packValue(newBinary(sha512(sender.identifier())));
                packer.packValue(newBinary(serialize(recipient.publicKey())));
                packer.packValue(newBinary(sha512(recipient.identifier())));
                return packer.toByteArray();
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }

        private byte[] replySalt(byte[] context) {
            return Crypto.kdfDeriveFromInputKeyMaterial(REPLY_SALT.getBytes(UTF_8), demKey.getKeyBytes(), context, 32);
        }
    }

    static byte[] keyId(byte[] salt, PublicKey publicKey) {
        return Arrays.copyOf(PRF.HS512.calculate(salt, serialize(publicKey)), 4);
    }

    static byte[] serialize(PublicKey pk) {
        if (isX25519Key(pk)) {
            return Arrays.copyOf(Utils.unsignedLittleEndian(((XECPublicKey) pk).getU()), 32);
        } else {
            throw new IllegalArgumentException("Invalid public key");
        }
    }

    static boolean isX25519Key(Key key) {
        return key instanceof XECKey xk && "X25519".equals(((NamedParameterSpec) xk.getParams()).getName());
    }

    static PublicKey deserialize(byte[] pk) {
        return CryptoBox.publicKey(pk);
    }

    static byte[] sha512(String string) {
        return Crypto.hash(string.getBytes(UTF_8));
    }
}
