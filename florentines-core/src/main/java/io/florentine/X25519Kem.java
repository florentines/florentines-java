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
import static io.florentine.Utils.threadLocal;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.msgpack.value.ValueFactory.newBinary;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import javax.crypto.KeyAgreement;

import org.msgpack.core.MessagePack;

final class X25519Kem extends KEM {
    private static final ThreadLocal<KeyAgreement> X25519 = threadLocal(() -> KeyAgreement.getInstance("X25519"));
    private static final ThreadLocal<KeyPairGenerator> KEY_PAIR_GENERATOR_THREAD_LOCAL =
            threadLocal(() -> KeyPairGenerator.getInstance("X25519"));
    private static final ThreadLocal<KeyFactory> KEY_FACTORY_THREAD_LOCAL =
            threadLocal(() -> KeyFactory.getInstance("X25519"));

    @Override
    public String identifier() {
        return "AuthKEM-X25519";
    }

    @Override
    KeyPair generateKeyPair() {
        return freshKeyPair();
    }

    static KeyPair freshKeyPair() {
        return KEY_PAIR_GENERATOR_THREAD_LOCAL.get().generateKeyPair();
    }

    @Override
    State begin(DEM dem, KeyPair local, Collection<PublicKey> remote) {
        Require.bothKeysPresent(local, "local keys");
        Require.notEmpty(remote, "remote keys");
        Require.matches(X25519Kem::isX25519Key, local.getPrivate(), "Local private key is not for X25519");
        Require.matches(X25519Kem::isX25519Key, local.getPublic(), "Local public key is not for X25519");
        Require.all(X25519Kem::isX25519Key, remote, "Remote public keys must all be X25519 keys");
        // NB we could also check that the local public key matches the private key, but this is expensive and we
        // prevent known attacks by including all PKs in the KDF inputs.


        var initialSalt = "Florentine-" + identifier() + "-" + dem.identifier();
        return new State(dem, local, generateKeyPair(), List.copyOf(remote), initialSalt.getBytes(UTF_8));
    }

    private static byte[] x25519(Key secretKey, PublicKey publicKey) {
        var x25519 = X25519.get();
        try {
            x25519.init(secretKey);
            x25519.doPhase(publicKey, true);
            return x25519.generateSecret();
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static final class State implements KEM.State {
        private volatile boolean destroyed = false;
        private final KeyPair localKeys;
        private final KeyPair ephemeralKeys;
        private final List<PublicKey> remoteKeys;
        private final byte[] kdfSalt;
        private final DEM dem;
        private final DestroyableSecretKey demKey;
        private final byte[] keyIdSalt;

        private State(DEM dem, KeyPair localKeys, KeyPair ephemeralKeys, List<PublicKey> remoteKeys, byte[] salt) {
            this.localKeys = requireNonNull(localKeys, "localKeys");
            this.ephemeralKeys = requireNonNull(ephemeralKeys, "ephemeralKeys");
            this.remoteKeys = requireNonNull(remoteKeys, "remoteKeys");
            this.kdfSalt = requireNonNull(salt, "salt");
            this.dem = requireNonNull(dem, "dem");
            this.demKey = dem.generateKey();
            this.keyIdSalt = PRF.HS512.calculate("Florentine-AuthKEM-X25519-KeyID-Salt".getBytes(UTF_8),
                    serialize(ephemeralKeys.getPublic()));

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
                out.packValue(newBinary(keyId(keyIdSalt, localKeys.getPublic())));
                out.packShort((short) remoteKeys.size());

                for (var recipient : remoteKeys) {
                    out.packValue(newBinary(keyId(keyIdSalt, recipient)));
                    var kdfContext = kdfContext(localKeys.getPublic(), recipient, ephemeralKeys.getPublic(),
                            context);
                    try (var wrapKey = keyAgreement(ephemeralKeys.getPrivate(), recipient,
                                                    localKeys.getPrivate(), recipient, kdfContext)) {
                        var wrapped = kw.wrap(wrapKey, demKey);
                        out.packValue(newBinary(wrapped));
                    }
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            var replyState = new State(dem, ephemeralKeys, freshKeyPair(), remoteKeys, replySalt(context));
            return new EncapsulatedKey(baos.toByteArray(), replyState);
        }

        @Override
        public Optional<DecapsulatedKey> decapsulate(byte[] encapsulatedKey, byte[] context) {
            try (var in = MessagePack.newDefaultUnpacker(new ByteArrayInputStream(encapsulatedKey))) {

                var epk = in.unpackValue().asBinaryValue().asByteArray();
                var ephemeralPk = deserialize(epk);
                var expectedKeyId = keyId(keyIdSalt, localKeys.getPublic());
                var remoteKid = in.unpackValue().asBinaryValue().asByteArray();

                var sender = remoteKeys.stream()
                        .filter(candidate -> Arrays.equals(remoteKid, keyId(keyIdSalt, candidate)))
                        .findAny();
                if (sender.isEmpty()) {
                    return Optional.empty();
                }

                var numRecipients = in.unpackShort();
                for (int i = 0; i < numRecipients; ++i) {
                    var kid = in.unpackValue().asBinaryValue().asByteArray();
                    var wrappedKey = in.unpackValue().asBinaryValue().asByteArray();

                    if (MessageDigest.isEqual(expectedKeyId, kid)) {
                        // A candidate...
                        var kdfContext = kdfContext(sender.get(), localKeys.getPublic(), ephemeralPk, context);
                        try (var unwrapKey = keyAgreement(localKeys.getPrivate(), ephemeralPk,
                                                          localKeys.getPrivate(), sender.get(), kdfContext)) {
                            var unwrappedKey = dem.asKeyWrapper().unwrap(unwrapKey, wrappedKey, dem.identifier());
                            if (unwrappedKey.isPresent()) {
                                var replyState = new State(dem, localKeys, freshKeyPair(), List.of(ephemeralPk),
                                        replySalt(context));
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
            // TODO: in a reply situation the local keys are actually ephemeral so we should destroy those too...
            Utils.destroy(ephemeralKeys.getPrivate(), demKey);
            destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }

        private DestroyableSecretKey keyAgreement(PrivateKey esPriv, PublicKey esPub, PrivateKey ssPriv,
                                                  PublicKey ssPub, byte[] context) {
            var es = emptyBytes();
            var ss = emptyBytes();
            var secret = emptyBytes();
            try {
                es = x25519(esPriv, esPub);
                ss = x25519(ssPriv, ssPub);
                secret = HKDF.hkdf(kdfSalt, Utils.concat(es, ss), context, 32);
                return new DestroyableSecretKey(secret, dem.identifier());
            } finally {
                Arrays.fill(secret, (byte) 0);
                Arrays.fill(es, (byte) 0);
                Arrays.fill(ss, (byte) 0);
            }
        }

        private byte[] kdfContext(PublicKey sender, PublicKey recipient, PublicKey epk, byte[] context) {
            // TODO: only the (fixed size) recipient PK changes, so we could reuse the byte buffer here
            try (var packer = MessagePack.newDefaultBufferPacker()) {
                packer.packValue(newBinary(context));
                packer.packValue(newBinary(serialize(epk)));
                packer.packValue(newBinary(serialize(sender)));
                packer.packValue(newBinary(serialize(recipient)));
                return packer.toByteArray();
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }

        private byte[] replySalt(byte[] context) {
            return HKDF.hkdf("Florentine-AuthKEM-X25519-Reply-Salt".getBytes(UTF_8), demKey.getKeyBytes(), context, 32);
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
        var u = new BigInteger(1, Utils.reverse(pk.clone()));
        try {
            return KEY_FACTORY_THREAD_LOCAL.get().generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u));
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
