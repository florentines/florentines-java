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

import static io.florentine.CC20HS512.hmac;
import static io.florentine.Utils.emptyBytes;
import static io.florentine.Utils.threadLocal;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.msgpack.value.ValueFactory.newBinary;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import javax.crypto.KeyAgreement;

import org.msgpack.core.MessagePack;

final class X25519Kem extends KEM {
    private static final ThreadLocal<KeyAgreement> X25519 = threadLocal(() -> KeyAgreement.getInstance("X25519"));

    @Override
    public String identifier() {
        return "AuthKEM-X25519";
    }

    @Override
    KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
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

        private State(DEM dem, KeyPair localKeys, KeyPair ephemeralKeys, List<PublicKey> remoteKeys, byte[] salt) {
            this.localKeys = requireNonNull(localKeys, "localKeys");
            this.ephemeralKeys = requireNonNull(ephemeralKeys, "ephemeralKeys");
            this.remoteKeys = requireNonNull(remoteKeys, "remoteKeys");
            this.kdfSalt = requireNonNull(salt, "salt");
            this.dem = requireNonNull(dem, "dem");
            this.demKey = dem.generateKey();

            Require.between(remoteKeys.size(), 1, 1<<16, "# remote keys must be between 1 and 65,535");
        }

        @Override
        public DestroyableSecretKey key() {
            return demKey;
        }

        @Override
        public EncapsulatedKey encapsulate(byte[] context) {
            byte[] es = emptyBytes();
            byte[] ss = emptyBytes();

            var epk = serialize(ephemeralKeys.getPublic());
            var keyIdSalt = hmac("Florentine-KeyID-Salt".getBytes(UTF_8), epk);

            var baos = new ByteArrayOutputStream();
            try (var out = MessagePack.newDefaultPacker(baos)) {
                out.packValue(newBinary(epk));
                out.packShort((short) remoteKeys.size());

                for (var recipient : remoteKeys) {
                    out.packValue(newBinary(keyId(keyIdSalt, recipient)));
                    try {
                        es = x25519(ephemeralKeys.getPrivate(), recipient);
                        ss = x25519(localKeys.getPrivate(), recipient);

                        try (var wrapKey = new DestroyableSecretKey(
                                HKDF.hkdf(kdfSalt, Utils.concat(es, ss), kdfContext(recipient, context), 32),
                                dem.identifier())) {
                            var wrapped = dem.wrap(wrapKey, demKey);
                            out.packValue(newBinary(wrapped));
                        }

                    } finally {
                        Arrays.fill(es, (byte) 0);
                        Arrays.fill(ss, (byte) 0);
                    }
                }
            } catch (IOException e) {
                // All in-memory, shouldn't ever produce an IOException...
                throw new AssertionError(e);
            }

            return null;
        }

        @Override
        public Optional<DecapsulatedKey> decapsulate(byte[] encapsulatedKey, byte[] context) {
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

        private byte[] kdfContext(PublicKey recipient, byte[] context) {
            try (var packer = MessagePack.newDefaultBufferPacker()) {
                packer.packValue(newBinary(context));
                packer.packValue(newBinary(serialize(ephemeralKeys.getPublic())));
                packer.packValue(newBinary(serialize(localKeys.getPublic())));
                packer.packValue(newBinary(serialize(recipient)));
                return packer.toByteArray();
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }
    }

    static byte[] keyId(byte[] salt, PublicKey publicKey) {
        return Arrays.copyOf(hmac(salt, serialize(publicKey)), 4);
    }

    static byte[] serialize(PublicKey pk) {
        if (pk instanceof XECPublicKey xpk &&
                "X25519".equals(((NamedParameterSpec) xpk.getParams()).getName())) {
            return Arrays.copyOf(Utils.unsignedLittleEndian(xpk.getU()), 32);
        } else {
            throw new IllegalArgumentException("Invalid public key");
        }
    }

}
