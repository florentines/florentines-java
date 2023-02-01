/*
 * Copyright 2023 Neil Madden.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.pando.crypto.nacl.Crypto;
import software.pando.crypto.nacl.Subtle;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import static io.florentine.crypto.Utils.checkState;
import static io.florentine.crypto.Utils.rejectIf;
import static io.florentine.crypto.X25519.PK_SIZE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

final class X25519AnonKEM implements AnonKEM {
    private static final Logger logger = LoggerFactory.getLogger(X25519AnonKEM.class);

    private static final int MAX_RECIPIENTS = 65535;

    private final DEM dem;

    X25519AnonKEM(DEM dem) {
        this.dem = dem;
    }

    @Override
    public String getAlgorithmIdentifier() {
        return "AnonKEM-X25519-" + dem.getAlgorithmIdentifier();
    }

    @Override
    public KEMState beginEncap(List<PublicKey> remotes, byte[] context) {
        var ephemeral = generateKeyPair();
        return new EncapsulationState(ephemeral, remotes, context);
    }

    @Override
    public KEMState beginDecap(KeyPair localKeys, byte[] context) {
        return new DecapsulationState(localKeys, context);
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    static byte[] kdfContext(byte[] userContext, PublicKey epk, PublicKey recipient) {
        byte[] kdfContext = new byte[userContext.length + 2*PK_SIZE];
        System.arraycopy(X25519.serializePublicKey(epk), 0, kdfContext, 0, PK_SIZE);
        System.arraycopy(X25519.serializePublicKey(recipient), 0, kdfContext, PK_SIZE, PK_SIZE);
        System.arraycopy(userContext, 0, kdfContext, 2*PK_SIZE, userContext.length);
        return kdfContext;
    }

    private class EncapsulationState implements KEMState {
        private final KeyPair ephemeral;
        private final List<PublicKey> pks;
        private final byte[] context;
        private final SecretKey demKey;

        public EncapsulationState(KeyPair ephemeral, List<PublicKey> pks, byte[] context) {
            this.ephemeral = requireNonNull(ephemeral, "ephemeral keys");
            this.pks = requireNonNull(pks, "public keys");
            this.context = requireNonNull(context, "context").clone();
            this.demKey = dem.generateKey();

            rejectIf(pks.isEmpty(), "Must specify at least one public key");
            rejectIf(pks.size() > MAX_RECIPIENTS, "Too many public keys: max=" + MAX_RECIPIENTS);
        }

        @Override
        public SecretKey key() {
            checkState(!isDestroyed(), "KEM state has been destroyed");
            return demKey;
        }

        @Override
        public byte[] encapsulate(byte[] tag) {
            checkState(!isDestroyed(), "KEM state has been destroyed");
            try (var out = new ByteArrayOutputStream()) {
                out.writeBytes(X25519.serializePublicKey(ephemeral.getPublic()));

                System.out.println("epk: " + HexFormat.of().formatHex(X25519.serializePublicKey(ephemeral.getPublic())));

                for (PublicKey pk : pks) {
                    var es = X25519.compute(ephemeral.getPrivate(), pk);
                    System.out.println("es : " + HexFormat.of().formatHex(es));
                    var salt = getAlgorithmIdentifier().getBytes(UTF_8);
                    var kdfContext = kdfContext(context, ephemeral.getPublic(), pk);
                    var wrapKey = dem.importKey(Crypto.kdfDeriveFromInputKeyMaterial(salt, es, kdfContext, 32));
                    Arrays.fill(es, (byte) 0);
                    System.out.println("wrapKey: " + HexFormat.of().formatHex(wrapKey.getEncoded()));
                    System.out.println("demKey : " + HexFormat.of().formatHex(demKey.getEncoded()));
                    System.out.println("tag    : " + HexFormat.of().formatHex(tag));
                    var wrapped = dem.wrap(wrapKey, demKey, tag);
                    Utils.destroy(wrapKey);
                    if (wrapped.length > 255) {
                        throw new AssertionError("Wrapped key is larger than 255 bytes");
                    }
                    System.out.println("WrappedKey: " + HexFormat.of().formatHex(wrapped));

                    // Write the first 4 bytes of a hash of the KDF context as an identifier. Recipients can
                    // quickly calculate this value and so reduce the number of candidate key blobs they need to
                    // consider. This provides some level of obscuring of their public key identity as the hash is
                    // effectively salted by the ephemeral pk.
                    var id = Crypto.hash(kdfContext);
                    out.write(id, 0, 4);

                    // TODO: remove explicit lengths here and have the DEM tell us how large this will be...
                    out.write(wrapped.length);
                    out.writeBytes(wrapped);
                }

                // NB: flush() not necessary for BAOS
                return out.toByteArray();
            } catch (IOException e) {
                // Shouldn't ever happen...
                throw new AssertionError("Unexpected IOException while generating encapsulated key", e);
            }
        }

        @Override
        public Optional<SecretKey> decapsulate(byte[] tag, byte[] encapsulation) {
            throw new IllegalStateException("KEM was initialized for encapsulation only");
        }

        @Override
        public void destroy() throws DestroyFailedException {
            if (isDestroyed()) {
                return;
            }
            DestroyFailedException first = null;
            try {
                demKey.destroy();
            } catch (DestroyFailedException ex) {
                first = ex;
            }
            try {
                ephemeral.getPrivate().destroy();
            } catch (DestroyFailedException ex) {
                if (first == null) {
                    first = ex;
                } else {
                    first.addSuppressed(ex);
                }
            }
            if (first != null) {
                throw first;
            }
        }

        @Override
        public boolean isDestroyed() {
            return demKey.isDestroyed() || ephemeral.getPrivate().isDestroyed();
        }
    }

    private class DecapsulationState implements KEMState {
        private final KeyPair localKeys;
        private final byte[] context;

        private DecapsulationState(KeyPair localKeys, byte[] context) {
            this.localKeys = requireNonNull(localKeys, "local keys");
            this.context = requireNonNull(context, "context");
        }

        @Override
        public SecretKey key() {
            throw new IllegalStateException("KEM not initialized for encapsulation");
        }

        @Override
        public byte[] encapsulate(byte[] tag) {
            throw new IllegalStateException("KEM not initialized for encapsulation");
        }

        @Override
        public Optional<SecretKey> decapsulate(byte[] tag, byte[] encapsulation) {
            requireNonNull(tag, "tag");
            requireNonNull(encapsulation, "encapsulation");
            if (encapsulation.length <= 64) {
                return Optional.empty();
            }
            try (var in = new ByteArrayInputStream(encapsulation)) {
                var epk = X25519.deserializePublicKey(in.readNBytes(32));
                System.out.println("epk: " + HexFormat.of().formatHex(X25519.serializePublicKey(epk)));

                var kdfContext = kdfContext(context, epk, localKeys.getPublic());
                var id = Crypto.hash(kdfContext);

                while (in.available() > 0) {
                    var candidateId = in.readNBytes(4);
                    var wrappedKeyLen = in.read();
                    if (wrappedKeyLen == -1) {
                        break;
                    }
                    var wrappedKey = in.readNBytes(wrappedKeyLen);

                    if (Arrays.equals(candidateId, 0, 4, id, 0, 4)) {
                        var es = Subtle.scalarMultiplication(localKeys.getPrivate(), epk);
                        System.out.println("es : " + HexFormat.of().formatHex(es));
                        var salt = getAlgorithmIdentifier().getBytes(UTF_8);
                        var wrapKey = dem.importKey(Crypto.kdfDeriveFromInputKeyMaterial(salt, es, kdfContext, 32));
                        Arrays.fill(es, (byte) 0);
                        System.out.println("wrapKey: " + HexFormat.of().formatHex(wrapKey.getEncoded()));
                        System.out.println("wrappedKey : " + HexFormat.of().formatHex(wrappedKey));
                        System.out.println("tag    : " + HexFormat.of().formatHex(tag));
                        var result = dem.unwrap(wrapKey, wrappedKey, dem::importKey, tag);
                        if (result.isPresent()) {
                            return result;
                        }
                    }
                }

            } catch (IOException e) {
                throw new AssertionError("Unexpected IOException while parsing encapsulated key", e);
            } catch (IllegalArgumentException e) {
                logger.debug("Invalid ephemeral public key", e);
            }

            return Optional.empty();
        }
    }

}
