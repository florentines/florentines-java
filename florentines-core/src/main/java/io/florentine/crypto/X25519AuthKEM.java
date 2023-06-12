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

import io.florentine.AlgorithmSuite;
import io.florentine.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.pando.crypto.nacl.Crypto;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

final class X25519AuthKEM implements AuthKEM {
    private static final Logger logger = LoggerFactory.getLogger(X25519AuthKEM.class);
    private static final String ALGORITHM_ID_PREFIX = "Florentine-AuthKEM-X25519-";
    private static final int MAX_RECIPIENTS = 65535;

    @Override
    public KeyPair generateKeyPair() {
        return X25519.generateKeyPair();
    }

    @Override
    public State begin(DEM dem, KeyPair local, List<PublicKey> remotes) {
        String algorithmIdentifier = ALGORITHM_ID_PREFIX + dem.getAlgorithmIdentifier();
        return new State(dem, local, generateKeyPair(), remotes, algorithmIdentifier.getBytes(UTF_8));
    }

    static byte[] kdfContext(PublicKey epk, PublicKey sender, PublicKey recipient) {
        return Utils.concat(
                X25519.serializePublicKey(epk),
                X25519.serializePublicKey(sender),
                X25519.serializePublicKey(recipient));
    }

    private final class State implements AuthKEM.State {
        private final DEM dem;
        private final KeyPair localKeys;
        private final KeyPair ephemeral;
        private final List<PublicKey> remoteKeys;
        private final byte[] salt;

        private SecretKey demKey;

        private State(DEM dem, KeyPair localKeys, KeyPair ephemeral, List<PublicKey> remoteKeys, byte[] salt) {
            this.dem = requireNonNull(dem, "DEM");
            this.localKeys = requireNonNull(localKeys, "local keys");
            this.ephemeral = requireNonNull(ephemeral, "ephemeral keys");
            this.remoteKeys = requireNonNull(remoteKeys, "remote keys");
            this.salt = requireNonNull(salt, "salt");

            Utils.rejectIf(remoteKeys.isEmpty(), "Must specify at least one public key");
            Utils.rejectIf(remoteKeys.size() > MAX_RECIPIENTS, "Too many public keys: max=" + MAX_RECIPIENTS);
        }

        @Override
        public AlgorithmSuite getAlgorithm() {
            // TODO: work out/pass correct algorithm to here
            return AlgorithmSuite.AUTHKEM_X25519_A256SIV_HS512;
        }

        @Override
        public SecretKey key() {
            Utils.checkState(!isDestroyed(), "KEM state has been destroyed");
            if (demKey == null) {
                demKey = dem.generateKey();
            }
            return demKey;
        }

        @Override
        public KeyEncapsulation encapsulate(byte[]... context) {
            Utils.checkState(!isDestroyed(), "KEM state has been destroyed");
            var demKey = key();
            try (var out = new ByteArrayOutputStream()) {
                out.writeBytes(X25519.serializePublicKey(ephemeral.getPublic()));

                for (PublicKey pk : remoteKeys) {
                    var kdfContext = kdfContext(ephemeral.getPublic(), localKeys.getPublic(), pk);
                    var wrapKey = deriveKey(ephemeral.getPrivate(), pk, localKeys.getPrivate(), pk, kdfContext);
                    var wrapped = dem.wrap(wrapKey, demKey, context);
                    Utils.destroy(wrapKey);
                    if (wrapped.length > 255) {
                        throw new AssertionError("Wrapped key is larger than 255 bytes");
                    }

                    // Write the first 4 bytes of a hash of the KDF context as an identifier. Recipients can
                    // quickly calculate this value and so reduce the number of candidate key blobs they need to
                    // consider. This provides some level of obscuring of their public key identity as the hash is
                    // effectively salted by the ephemeral pk.
                    var id = Crypto.hash(kdfContext);
                    out.write(id, 0, 4);

                    out.write(wrapped.length);
                    out.writeBytes(wrapped);
                }

                // NB: flush() not necessary for BAOS
                var encapsulation = out.toByteArray();
                var replyState = new State(dem, ephemeral, generateKeyPair(), remoteKeys,
                        dem.hash(demKey.getEncoded()));

                return new KeyEncapsulation(replyState, encapsulation);

            } catch (IOException e) {
                // Shouldn't ever happen...
                throw new AssertionError("Unexpected IOException while generating encapsulated key", e);
            } finally {
                Utils.destroy(demKey);
                this.demKey = null;
            }
        }

        @Override
        public Optional<DecapsulatedKey> decapsulate(byte[] encapsulation, byte[]... context) {
            requireNonNull(context, "context");
            requireNonNull(encapsulation, "encapsulation");
            if (encapsulation.length <= 64) {
                return Optional.empty();
            }

            try (var in = new ByteArrayInputStream(encapsulation)) {
                var epk = X25519.deserializePublicKey(in.readNBytes(32));

                var keyMap = new TreeMap<byte[], KeyContext>(Arrays::compare);
                for (var pk : remoteKeys) {
                    var kdfContext = kdfContext(epk, remoteKeys.get(0), localKeys.getPublic());
                    var id = Arrays.copyOf(Crypto.hash(kdfContext), 4);
                    keyMap.put(id, new KeyContext(pk, kdfContext));
                }

                while (in.available() > 0) {
                    var candidateId = in.readNBytes(4);
                    var wrappedKeyLen = in.read();
                    if (wrappedKeyLen == -1) {
                        break;
                    }
                    var wrappedKey = in.readNBytes(wrappedKeyLen);

                    var keyContext = keyMap.get(candidateId);
                    if (keyContext != null) {
                        var wrapKey = deriveKey(localKeys.getPrivate(), epk, localKeys.getPrivate(), keyContext.pk,
                                keyContext.kdfContext);
                        var decrypted = dem.unwrap(wrapKey, wrappedKey, dem::importKey, context);
                        if (decrypted.isPresent()) {
                            return decrypted.map(demKey -> {
                                var replyState = new State(dem,
                                        localKeys,
                                        generateKeyPair(),              // new ephemeral
                                        List.of(keyContext.pk),         // remote key
                                        dem.hash(demKey.getEncoded())); // new KDF salt
                                return new DecapsulatedKey(replyState, demKey);
                            });
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

        private SecretKey deriveKey(PrivateKey esPriv, PublicKey esPub, PrivateKey ssPriv, PublicKey ssPub,
                                    byte[] context) {
            byte[] es = null, ss = null, secret = null;
            try {
                es = X25519.compute(esPriv, esPub);
                ss = X25519.compute(ssPriv, ssPub);
                secret = Utils.concat(es, ss);
                return dem.importKey(Crypto.kdfDeriveFromInputKeyMaterial(salt, secret, context, 32));
            } finally {
                if (es != null) { Arrays.fill(es, (byte) 0); }
                if (ss != null) { Arrays.fill(ss, (byte) 0); }
                if (secret != null) { Arrays.fill(secret, (byte) 0); }
            }
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
            return ephemeral.getPrivate() != null && ephemeral.getPrivate().isDestroyed();
        }
    }

    private record KeyContext(PublicKey pk, byte[] kdfContext) { }
}
