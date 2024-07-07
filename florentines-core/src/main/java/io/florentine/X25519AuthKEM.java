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
import static io.florentine.CryptoUtils.x25519;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.msgpack.core.MessagePack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.florentine.keys.PrivateKeySet;
import io.florentine.keys.PublicKeySet;

final class X25519AuthKEM implements AuthKEM {
    private static final Logger logger = LoggerFactory.getLogger(X25519AuthKEM.class);

    private static final PublicKey CURVE25519_BASEPOINT;

    static {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("XDH");
            CURVE25519_BASEPOINT = keyFactory.generatePublic(
                    new XECPublicKeySpec(NamedParameterSpec.X25519, BigInteger.valueOf(9)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private final CryptoSuite cryptoSuite;
    private final DEM dem;

    X25519AuthKEM(CryptoSuite cryptoSuite) {
        this.cryptoSuite = requireNonNull(cryptoSuite, "cryptoSuite");
        if (!(cryptoSuite.kem() instanceof X25519AuthKEM)) {
            throw new IllegalArgumentException("CryptoSuite KEM is not this KEM!");
        }
        this.dem = cryptoSuite.dem();
    }

    @Override
    public ValidKeyPair generateKeyPair() {
        logger.trace("Generating X25519 keypair");
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("X25519");
            var keyPair = keyPairGenerator.generateKeyPair();
            return new ValidKeyPair(cryptoSuite, keyPair.getPrivate(), keyPair.getPublic());
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    @Override
    public ValidKeyPair validateKeyPair(KeyPair keyPair) {
        requireNonNull(keyPair);
        requireNonNull(keyPair.getPublic(), "public key");
        requireNonNull(keyPair.getPrivate(), "private key");
        if (!isX25519Key(keyPair.getPrivate())) {
            throw new IllegalArgumentException("Not an X25519 private key");
        }
        validatePublicKey(keyPair.getPublic());

        // Check that the private key actually corresponds to this public key
        var computedX = x25519(keyPair.getPrivate(), CURVE25519_BASEPOINT);
        var providedX = serialize(keyPair.getPublic());
        if  (!Arrays.equals(computedX, providedX)) {
            throw new IllegalArgumentException("Public key doesn't match private key");
        }
        return new ValidKeyPair(cryptoSuite, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Override
    public ValidPublicKey validatePublicKey(PublicKey publicKey) {
        requireNonNull(publicKey);
        if (!isX25519Key(publicKey)) {
            throw new IllegalArgumentException("not an X25519 public key");
        }
        return new ValidPublicKey(cryptoSuite, publicKey);
    }

    @Override
    public KemState begin(PrivateKeySet localParty, Collection<PublicKeySet> remoteParties) {
        logger.trace("Beginning KEM state: localKeys={}, remoteKeys={}", localParty,
                remoteParties);
        requireNonNull(localParty, "Local party key-pair");
        requireNonNull(remoteParties, "Remote party public keys");
        if (remoteParties.isEmpty()) {
            throw new IllegalArgumentException("No remote parties supplied");
        }

        var application = localParty.application();
        var aliceKeys = localParty.keys().stream()
                .filter(key -> key.algorithm() == cryptoSuite)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No suitable local key in keyset"));
        var localKeyInfo = new LocalKeyInfo(localParty.contextInfo(),
                validateKeyPair(new KeyPair(aliceKeys.publicKey(), aliceKeys.privateKey())));

        var remoteKeyInfo = new ArrayList<RemoteKeyInfo>(remoteParties.size());
        for (var bob : remoteParties) {
            if (!application.equals(bob.application())) {
                throw new IllegalArgumentException("Application mismatch");
            }
            var keyInfo = bob.keys().stream()
                    .filter(key -> key.algorithm() == cryptoSuite)
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("No suitable remote key in keyset"));
            remoteKeyInfo.add(new RemoteKeyInfo(bob.contextInfo(), validatePublicKey(keyInfo.pk())));
        }

        var ephemeralKeys = generateKeyPair();
        return new X25519KemState(application, localKeyInfo, ephemeralKeys, remoteKeyInfo,
                cryptoSuite.identifier().getBytes(US_ASCII));
    }

    private record LocalKeyInfo(byte[] contextInfo, ValidKeyPair keyPair) {}
    private record RemoteKeyInfo(byte[] contextInfo, ValidPublicKey publicKey) {}

    private final class X25519KemState implements KemState {

        private final String applicationLabel;
        private final LocalKeyInfo localParty;
        private final ValidKeyPair ephemeralKeys;
        private final List<RemoteKeyInfo> remoteParties;
        private final byte[] salt;

        private DataKey messageKey;

        private X25519KemState(String applicationLabel, LocalKeyInfo localParty, ValidKeyPair ephemeralKeys,
                               List<RemoteKeyInfo> remoteParties,
                               byte[] salt) {
            this.applicationLabel = applicationLabel;
            this.localParty = localParty;
            this.ephemeralKeys = ephemeralKeys;
            this.remoteParties = remoteParties;
            this.salt = salt;
        }

        @Override
        public DataKey key() {
            if (messageKey == null) {
                logger.debug("Generating DEK");
                messageKey = dem.importKey(CryptoUtils.randomBytes(dem.keySizeBytes()));
            }
            return messageKey;
        }

        @Override
        public KeyEncapsulation encapsulate(byte[] context) {
            if (isDestroyed()) {
                throw new IllegalStateException("destroyed");
            }
            if (localParty.keyPair().privateKey() == null) {
                throw new IllegalStateException("no local private key");
            }

            var encapsulation = new ByteArrayOutputStream();
            try (var out = new DataOutputStream(encapsulation);
                 var dek = key()) {
                out.write(serialize(ephemeralKeys.publicKey())); // 32 bytes
                out.write(keyId(localParty.keyPair().publicKey())); // 2 bytes
                out.writeShort(remoteParties.size()); // 2 bytes

                var keyWrapper = dem.asKeyWrapper();
                for (var recipient : remoteParties) {
                    var recipientPk = recipient.publicKey().publicKey();
                    out.write(keyId(recipientPk)); // 2 bytes
                    var kdfContext = kdfContext(recipient);

                    var es = CryptoUtils.x25519(ephemeralKeys.privateKey(), recipientPk);
                    var ss = CryptoUtils.x25519(localParty.keyPair().privateKey(), recipientPk);

                    try (var prk = HKDF.extract(salt, concat(es, ss));
                         var kek = HKDF.expandToKey(prk, kdfContext, 64, keyWrapper.identifier())) {
                        var wrapped = keyWrapper.wrap(kek, dek, context);
                        out.write(wrapped); // 48 bytes
                    } finally {
                        CryptoUtils.wipe(es, ss);
                    }
                }

                var replySalt = replySalt(context, dek);
                var ephemeralKeyInfo = new LocalKeyInfo(localParty.contextInfo, ephemeralKeys);
                var replyState = new X25519KemState(applicationLabel, ephemeralKeyInfo, generateKeyPair(),
                        remoteParties, replySalt);
                return new KeyEncapsulation(replyState, encapsulation.toByteArray());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        byte[] replySalt(byte[] context, DataKey dek) {
            return HKDF.expand(
                    HKDF.extract(("Florentine-Reply-Salt-" + cryptoSuite.identifier()).getBytes(US_ASCII),
                            dek.keyMaterial()),
                    context, 32);
        }

        private byte[] kdfContext(RemoteKeyInfo recipient) {
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
                var partyUInfo = localParty.contextInfo();
                out.packBinaryHeader(partyUInfo.length);
                out.writePayload(partyUInfo);

                var partyUPk = serialize(localParty.keyPair().publicKey());
                out.packBinaryHeader(partyUPk.length);
                out.addPayload(partyUPk);
                var epk = serialize(ephemeralKeys.publicKey());
                out.packBinaryHeader(epk.length);
                out.addPayload(epk);

                // PartyVInfo
                var partyVInfo = recipient.contextInfo();
                out.packBinaryHeader(partyVInfo.length);
                out.addPayload(partyVInfo);

                var partyVPk = serialize(recipient.publicKey().publicKey());
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
            var salt = serialize(ephemeralKeys.publicKey());
            try (var tmp = HKDF.extract(salt, serialize(pk))) {
                return Arrays.copyOf(tmp.getEncoded(), 2);
            }
        }

        @Override
        public Optional<KeyDecapsulation> decapsulate(byte[] encapsulatedKey, byte[] context) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void writeTo(OutputStream out) throws IOException {
            if (isDestroyed()) {
                throw new IllegalStateException("kem state has been destroyed");
            }
            throw new UnsupportedOperationException();
        }

        @Override
        public void destroy() {
            CryptoUtils.destroy(messageKey, ephemeralKeys.privateKey());
        }

        @Override
        public boolean isDestroyed() {
            return messageKey.isDestroyed() || ephemeralKeys.privateKey().isDestroyed();
        }
    }
}
