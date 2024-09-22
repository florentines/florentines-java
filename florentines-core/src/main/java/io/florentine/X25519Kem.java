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
        return KEY_PAIR_GENERATOR_THREAD_LOCAL.get().generateKeyPair();
    }

    @Override
    State begin(DEM dem, KeySet local, Collection<KeySet> remote) {
        return null;
    }

    private static void validateKeys(KeySet local, Collection<KeySet> remote) {
        var app = local.getApplication();
        if (!remote.stream().allMatch(ks -> ks.getApplication().equals(app))) {
            throw new IllegalArgumentException("KeySet applications don't match");
        }
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
            this.keyIdSalt = HS512.HS512.calculate("Florentine-X25519-KeyID-Salt".getBytes(UTF_8),
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

            var newEphemeralKeys = KEY_PAIR_GENERATOR_THREAD_LOCAL.get().generateKeyPair();
            var newSalt = HKDF.extract(demKey.getKeyBytes(), context);
            var replyState = new State(dem, ephemeralKeys, newEphemeralKeys, remoteKeys,
                    newSalt);
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
                                // TODO: what is the reply state here...

                                return Optional.of(new DecapsulatedKey(unwrappedKey.get(), sender.get(), null));
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
            Utils.destroy(ephemeralKeys.getPrivate(), localKeys.getPrivate(), demKey);
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
            // TODO: only the recipient PK changes
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
    }

    static byte[] keyId(byte[] salt, PublicKey publicKey) {
        return Arrays.copyOf(PRF.HS512.calculate(salt, serialize(publicKey)), 4);
    }

    static byte[] serialize(PublicKey pk) {
        if (pk instanceof XECPublicKey xpk &&
                "X25519".equals(((NamedParameterSpec) xpk.getParams()).getName())) {
            return Arrays.copyOf(Utils.unsignedLittleEndian(xpk.getU()), 32);
        } else {
            throw new IllegalArgumentException("Invalid public key");
        }
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
