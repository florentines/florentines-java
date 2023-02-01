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
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

final class X25519AuthKEM implements AuthKEM {
    private static final Logger logger = LoggerFactory.getLogger(X25519AuthKEM.class);
    private static final int MAX_RECIPIENTS = 65535;

    private final DEM dem;

    X25519AuthKEM(DEM dem) {
        this.dem = dem;
    }

    @Override
    public String getAlgorithmIdentifier() {
        return "AuthKEM-X25519-" + dem.getAlgorithmIdentifier();
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    @Override
    public KEMState begin(KeyPair local, List<PublicKey> remotes, byte[] context) {
        return new State(local, generateKeyPair(), remotes, context);
    }

    static byte[] kdfContext(byte[] userContext, PublicKey epk, PublicKey sender, PublicKey recipient) {
        byte[] kdfContext = new byte[userContext.length + 3* X25519.PK_SIZE];
        System.arraycopy(X25519.serializePublicKey(epk), 0, kdfContext, 0, X25519.PK_SIZE);
        System.arraycopy(X25519.serializePublicKey(sender), X25519.PK_SIZE, kdfContext, X25519.PK_SIZE, X25519.PK_SIZE);
        System.arraycopy(X25519.serializePublicKey(recipient), 0, kdfContext, 2* X25519.PK_SIZE, X25519.PK_SIZE);
        System.arraycopy(userContext, 0, kdfContext, 3* X25519.PK_SIZE, userContext.length);
        return kdfContext;
    }

    private class State implements KEMState {
        private final KeyPair localKeys;
        private final KeyPair ephemeral;
        private final List<PublicKey> remoteKeys;
        private final byte[] context;

        private SecretKey demKey;

        private State(KeyPair localKeys, KeyPair ephemeral, List<PublicKey> remoteKeys, byte[] context) {
            this.localKeys = requireNonNull(localKeys, "local keys");
            this.ephemeral = requireNonNull(ephemeral, "ephemeral keys");
            this.remoteKeys = requireNonNull(remoteKeys, "remote keys");
            this.context = requireNonNull(context, "context");

            Utils.rejectIf(remoteKeys.isEmpty(), "Must specify at least one public key");
            Utils.rejectIf(remoteKeys.size() > MAX_RECIPIENTS, "Too many public keys: max=" + MAX_RECIPIENTS);
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
        public byte[] encapsulate(byte[] tag) {
            Utils.checkState(!isDestroyed(), "KEM state has been destroyed");
            var demKey = key();
            try (var out = new ByteArrayOutputStream()) {
                out.writeBytes(X25519.serializePublicKey(ephemeral.getPublic()));

                for (PublicKey pk : remoteKeys) {
                    var es = Subtle.scalarMultiplication(ephemeral.getPrivate(), pk);
                    var ss = Subtle.scalarMultiplication(localKeys.getPrivate(), pk);
                    var secret = Utils.concat(es, ss);
                    Arrays.fill(es, (byte) 0);
                    Arrays.fill(ss, (byte) 0);
                    var salt = getAlgorithmIdentifier().getBytes(UTF_8);
                    var kdfContext = kdfContext(context, ephemeral.getPublic(), localKeys.getPublic(), pk);
                    var wrapKey = dem.importKey(Crypto.kdfDeriveFromInputKeyMaterial(salt, secret, kdfContext, 32));
                    Arrays.fill(secret, (byte) 0);
                    var wrapped = dem.wrap(wrapKey, demKey, tag);
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
                return out.toByteArray();
            } catch (IOException e) {
                // Shouldn't ever happen...
                throw new AssertionError("Unexpected IOException while generating encapsulated key", e);
            }
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

                var keyMap = new TreeMap<byte[], KeyContext>(Arrays::compare);
                for (var pk : remoteKeys) {
                    var kdfContext = kdfContext(context, epk, remoteKeys.get(0), localKeys.getPublic());
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
                        var es = Subtle.scalarMultiplication(localKeys.getPrivate(), epk);
                        var ss = X25519.compute(localKeys.getPrivate(), keyContext.pk);
                        var secret = Utils.concat(es, ss);
                        Arrays.fill(es, (byte) 0);
                        Arrays.fill(ss, (byte) 0);

                        var salt = getAlgorithmIdentifier().getBytes(UTF_8);
                        var wrapKey = dem.importKey(
                                Crypto.kdfDeriveFromInputKeyMaterial(salt, secret, keyContext.kdfContext, 32));
                        Arrays.fill(secret, (byte) 0);
                        var decrypted = dem.unwrap(wrapKey, wrappedKey, dem::importKey, tag);
                        if (decrypted.isPresent()) {
                            return decrypted;
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
