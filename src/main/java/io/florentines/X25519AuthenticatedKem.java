/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines;

import static io.florentines.Algorithm.AUTHKEM_X25519_HKDF_A256SIV_HS256;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;
import static java.util.function.Predicate.not;
import static java.util.stream.Collectors.toUnmodifiableList;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.crypto.KeyAgreement;
import javax.security.auth.DestroyFailedException;

import org.slf4j.Logger;


final class X25519AuthenticatedKem implements KEM {
    private static final Logger logger = RedactedLogger.getLogger(X25519AuthenticatedKem.class);

    private static final KeyPairGenerator KEY_PAIR_GENERATOR;
    private static final KeyFactory KEY_FACTORY;
    private static final ThreadLocal<KeyAgreement> KEY_AGREEMENT_THREAD_LOCAL =
            ThreadLocal.withInitial(() -> {
                try {
                    return KeyAgreement.getInstance("X25519");
                } catch (NoSuchAlgorithmException e) {
                    throw new AssertionError("X25519 not supported", e);
                }
            });

    static {
        try {
            KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("X25519");
            KEY_FACTORY = KeyFactory.getInstance("X25519");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("X25519 not supported", e);
        }
    }

    private final DEM dem;

    X25519AuthenticatedKem(DEM dem) {
        this.dem = dem;
    }

    @Override
    public String getIdentifier() {
        return "AuthKEM-X25519-HKDF-" + dem.getIdentifier();
    }

    @Override
    public PrivateIdentity generateKeys(String application, String subject) {
        KeyPair keyPair;
        synchronized (KEY_PAIR_GENERATOR) {
            keyPair = KEY_PAIR_GENERATOR.generateKeyPair();
        }
        var encodedPubKey = encodePublicKey(keyPair.getPublic());
        var pubKey = new PublicIdentity(encodedPubKey, getIdentifier(), application, subject);
        return new PrivateIdentity(keyPair.getPrivate(), pubKey);
    }

    private static byte[] encodePublicKey(PublicKey pk) {
        assert pk instanceof XECPublicKey;
        return Utils.toUnsignedLittleEndian(((XECPublicKey) pk).getU(), 32);
    }

    @Override
    public State begin(PrivateIdentity localParty, PublicIdentity... remoteParties) {
        validateKeys(localParty, List.of(remoteParties));
        var myKeys = decodePrivateKey(localParty);
        var pubKeys = stream(remoteParties).map(X25519AuthenticatedKem::decodePublicKey).collect(toUnmodifiableList());
        var salt = Crypto.hash(("Florentine-" + getIdentifier()).getBytes(UTF_8));
        return internalBegin(localParty.getPublicIdentity().getApplication(), myKeys, pubKeys,
                any -> salt.clone());
    }

    private State internalBegin(String application, KeyPair privateKeys, List<PublicKey> publicKeys,
            Function<PublicKey, byte[]> salt) {
        return new State(application, privateKeys, publicKeys, salt);
    }

    @Override
    public DestroyableSecretKey demKey(ConversationState state) {
        return validateState(state).getDemKey();
    }

    @Override
    public Pair<ConversationState, byte[]> authEncap(ConversationState stateArg, byte[] tag) {
        var state = validateState(stateArg);
        var encodedEpk = encodePublicKey(state.getEphemeralKeys().getPublic());

        assert "RAW".equalsIgnoreCase(state.getDemKey().getFormat()) : "DEM key is not RAW format";
        var encodedDemKey = state.getDemKey().getEncoded();
        var baos = new ByteArrayOutputStream();
        var salts = new HashMap<PublicKey, byte[]>();
        try (var out = new DataOutputStream(baos)) {

            var saltedSenderKeyId = saltedKeyId(encodedEpk, state.localKeys.getPublic());

            out.write(encodedEpk); // 32 bytes
            out.write(saltedSenderKeyId); // 4 bytes
            out.writeShort(state.remoteKeys.size()); // 2 bytes

            for (var recipient : state.remoteKeys) {
                var keyId = saltedKeyId(encodedEpk, recipient);
                var salt = state.getKdfSaltFor(recipient)
                        .orElseThrow(() -> new IllegalStateException("Unable to determine KDF salt for recipient"));
                var keys = keyAgreement(state.getEphemeralKeys().getPrivate(), recipient,
                        state.localKeys.getPrivate(), recipient, salt,
                        kdfContext(state.application, state.localKeys.getPublic(), recipient,
                                state.getEphemeralKeys().getPublic()));

                var wrapKey = keys.getFirst();
                var chainingKey = keys.getSecond();
                salts.put(recipient, chainingKey);

                try {
                    var wrapped = wrap(wrapKey, encodedDemKey, tag);
                    out.write(keyId); // 4 bytes
                    out.write(wrapped); // 48 bytes
                } finally {
                    wrapKey.destroy();
                }
            }

        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        var newState = internalBegin(state.application, state.getEphemeralKeys(), state.remoteKeys, salts::get);
        return Pair.of(newState, baos.toByteArray());
    }

    private byte[] kdfContext(String application, PublicKey sender, PublicKey recipient, PublicKey epk) throws IOException {
        var baos = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(baos)) {
            out.writeUTF(getIdentifier());
            out.writeUTF(application);
            out.write(encodePublicKey(sender));
            out.write(encodePublicKey(recipient));
            out.write(encodePublicKey(epk));
        }
        return baos.toByteArray();
    }

    @Override
    public Optional<Pair<ConversationState, DestroyableSecretKey>> authDecap(ConversationState stateArg,
            byte[] encapKey, byte[] tag) {
        var state = validateState(stateArg);

        try (var in = new DataInputStream(new ByteArrayInputStream(encapKey))) {

            var encodedEpk = in.readNBytes(32);
            var epk = decodePublicKey(encodedEpk);

            var senderKeyId = in.readNBytes(4);

            return findSenderKey(encodedEpk, senderKeyId, state.remoteKeys).flatMap(senderKey -> {
                try {
                    var numRecipients = in.readUnsignedShort();
                    Optional<Pair<ConversationState, DestroyableSecretKey>> result = Optional.empty();
                    for (int i = 0; i < numRecipients; ++i) {
                        var keyId = in.readNBytes(4);
                        var wrappedKey = in.readNBytes(48);
                        var expectedKeyId = saltedKeyId(encodedEpk, state.localKeys.getPublic());

                        logger.trace("Comparing salted Key ID: expected={}, provided={}", Utils.hex(expectedKeyId),
                                Utils.hex(keyId));
                        if (result.isEmpty() && MessageDigest.isEqual(expectedKeyId, keyId)) {
                            var salt = state.getKdfSaltFor(senderKey);
                            if (salt.isEmpty()) {
                                logger.debug("No KDF salt in KEM state for key: {}", senderKey);
                                continue;
                            }
                            var keys = keyAgreement(state.localKeys.getPrivate(), epk,
                                    state.localKeys.getPrivate(), senderKey, salt.orElseThrow(),
                                    kdfContext(state.application, senderKey, state.localKeys.getPublic(), epk));

                            var wrapKey = keys.getFirst();
                            var chainingKey = keys.getSecond();

                            try {
                                var unwrapped = unwrap(wrapKey, wrappedKey, tag);
                                // Key IDs are only 4 bytes, so a matching Key ID doesn't guarantee that it is for us -
                                // if unwrapping fails, then continue trying other wrapped key blobs
                                result = unwrapped.map(demKey -> {
                                    var newState = internalBegin(state.application, state.localKeys, List.of(epk),
                                            any -> chainingKey);
                                    return Pair.of(newState, demKey);
                                });
                            } finally {
                                wrapKey.destroy();
                            }
                        }
                    }

                    return result;
                } catch (IOException e) {
                    return Optional.empty();
                }
            });
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private Pair<DestroyableSecretKey, byte[]> keyAgreement(PrivateKey sk1, PublicKey pk1, PrivateKey sk2,
            PublicKey pk2, byte[] salt, byte[] context) {
        byte[] ephemeralStatic = null, staticStatic = null, outputKeyMaterial = null;
        DestroyableSecretKey sharedSecret = null;

        logger.trace("KDF salt: {}, context: {}", salt, context);

        try {
            ephemeralStatic = x25519(sk1, pk1);
            staticStatic = x25519(sk2, pk2);
            sharedSecret = new DestroyableSecretKey(Crypto.HMAC_ALGORITHM,
                    HKDF.extract(ephemeralStatic, staticStatic, salt));
            outputKeyMaterial = HKDF.expand(sharedSecret, context, 64);
            var wrapKey = dem.importKey(Arrays.copyOf(outputKeyMaterial, 32));
            var chainingKey = Arrays.copyOfRange(outputKeyMaterial, 32, 64);

            if (logger.isTraceEnabled()) {
                logger.trace("Key agreement: es={}, ss={}, sharedSecret={}, okm={}",
                        ephemeralStatic, staticStatic, sharedSecret, outputKeyMaterial);
            }

            return Pair.of(wrapKey, chainingKey);
        } finally {
            if (ephemeralStatic != null) { Arrays.fill(ephemeralStatic, (byte) 0); }
            if (staticStatic != null) { Arrays.fill(staticStatic, (byte) 0); }
            if (sharedSecret != null) { sharedSecret.destroy(); }
            if (outputKeyMaterial != null) { Arrays.fill(outputKeyMaterial, (byte) 0); }
        }
    }

    private static Optional<PublicKey> findSenderKey(byte[] salt, byte[] saltedKeyId, List<PublicKey> candidates) {
        return candidates.stream()
                .filter(pk -> Arrays.equals(saltedKeyId(salt, pk), saltedKeyId))
                .findAny();
    }

    private void validateKeys(PrivateIdentity privateKey, List<PublicIdentity> publicKeys) {
        requireNonNull(privateKey, "Private key");
        requireNonNull(publicKeys, "Public key list");
        if (publicKeys.isEmpty()) {
            throw new IllegalArgumentException("No public keys provided");
        }
        if (publicKeys.size() > 65535) {
            throw new IllegalArgumentException("Too many public keys");
        }
        if (!(privateKey.getSecretKey() instanceof XECPrivateKey)) {
            throw new IllegalArgumentException("Invalid private key - should be a XECPrivateKey");
        }
        publicKeys.forEach(X25519AuthenticatedKem::decodePublicKey);

        var expectedAlgorithm = getIdentifier();
        if (!expectedAlgorithm.equals(privateKey.getPublicIdentity().getAlgorithmIdentifier())) {
            throw new IllegalArgumentException("Private key not intended for this algorithm");
        }
        if (publicKeys.stream().map(PublicIdentity::getAlgorithmIdentifier).anyMatch(not(expectedAlgorithm::equals))) {
            throw new IllegalArgumentException("At least one public key is for a different algorithm");
        }
        var expectedApplication = privateKey.getPublicIdentity().getApplication();
        if (publicKeys.stream().map(PublicIdentity::getApplication)
                .anyMatch(not(expectedApplication::equals))) {
            throw new IllegalArgumentException("At least one public key is for a different application");
        }
    }

    private static KeyPair decodePrivateKey(PrivateIdentity privateIdentity) {
        var privateKey = (XECPrivateKey) privateIdentity.getSecretKey();
        var publicKey = decodePublicKey(privateIdentity.getPublicIdentity());
        return new KeyPair(publicKey, privateKey);
    }

    private static PublicKey decodePublicKey(PublicIdentity publicKey) {
        return decodePublicKey(publicKey.getPublicKeyMaterial());
    }

    private static PublicKey decodePublicKey(byte[] encoded) {
        var decodedPubKey = Utils.fromUnsignedLittleEndian(encoded);
        synchronized (KEY_FACTORY) {
            try {
                return KEY_FACTORY.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, decodedPubKey));
            } catch (InvalidKeySpecException e) {
                throw new IllegalArgumentException("Invalid public key", e);
            }
        }
    }

    private static byte[] x25519(PrivateKey privateKey, PublicKey publicKey) {
        var keyAgreement = KEY_AGREEMENT_THREAD_LOCAL.get();
        try {
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret();
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static byte[] saltedKeyId(byte[] salt, PublicKey pk) {
        return Arrays.copyOf(HKDF.extract(encodePublicKey(pk), salt), 4);
    }

    private byte[] wrap(DestroyableSecretKey wrapKey, byte[] encodedDemKey, byte[] demTag) {
        byte[] encrypted = encodedDemKey.clone();
        byte[] siv =
                dem.beginEncryption(wrapKey)
                        .authenticate(demTag)
                        .encryptAndAuthenticate(encrypted)
                        .done().getFirst();
        return Utils.concat(siv, encrypted);
    }

    private Optional<DestroyableSecretKey> unwrap(DestroyableSecretKey wrapKey, byte[] wrappedKey, byte[] demTag) {
        var siv = Arrays.copyOf(wrappedKey, 16);
        var encrypted = Arrays.copyOfRange(wrappedKey, 16, wrappedKey.length);
        return dem.beginDecryption(wrapKey, siv)
                .authenticate(demTag)
                .decryptAndAuthenticate(encrypted)
                .verify()
                .map(ignored -> dem.importKey(encrypted));
    }

    private static State validateState(ConversationState stateArg) {
        Utils.require(stateArg instanceof State, "Invalid state object");
        return (State) stateArg;
    }

    static final class State implements ConversationState {
        final String application;
        final KeyPair localKeys;
        final List<PublicKey> remoteKeys;
        private final Function<PublicKey, byte[]> kdfSalt;

        private KeyPair ephemeralKeys;
        private DestroyableSecretKey demKey;

        State(String application, KeyPair localKeys, List<PublicKey> remoteKeys,
                Function<PublicKey, byte[]> kdfSalt) {
            this.application = requireNonNull(application, "application");
            this.localKeys = requireNonNull(localKeys, "local keys");
            this.remoteKeys = requireNonNull(remoteKeys, "remote keys");
            this.kdfSalt = requireNonNull(kdfSalt, "KDF salt function");

            if (remoteKeys.isEmpty() || remoteKeys.size() > 65535) {
                throw new IllegalArgumentException("Must be at least 1 and at most 65535 public keys");
            }
        }

        KeyPair getEphemeralKeys() {
            if (ephemeralKeys == null) {
                var keyPair = AUTHKEM_X25519_HKDF_A256SIV_HS256.generateKeys("dummy", "dummy");
                var privateKey = keyPair.getSecretKey();
                var publicKey = decodePublicKey(keyPair.getPublicIdentity().getPublicKeyMaterial());
                ephemeralKeys = new KeyPair(publicKey, (XECPrivateKey) privateKey);
            }
            return ephemeralKeys;
        }

        DestroyableSecretKey getDemKey() {
            if (demKey == null) {
                demKey = AUTHKEM_X25519_HKDF_A256SIV_HS256.dem.generateFreshKey();
            }
            return demKey;
        }

        @Override
        public void writeTo(OutputStream outputStream) throws IOException {
            var out = new DataOutputStream(new DeflaterOutputStream(outputStream, new Deflater(Deflater.DEFLATED, true)));
            try {
                out.writeUTF(AUTHKEM_X25519_HKDF_A256SIV_HS256.getIdentifier());
                out.writeUTF(application);
                writeKeyPair(localKeys, out);
                out.writeShort(remoteKeys.size());
                for (var pk : remoteKeys) {
                    var encoded = Utils.toUnsignedLittleEndian(((XECPublicKey) pk).getU(), 32);
                    out.write(encoded);
                    var salt = kdfSalt.apply(pk);
                    out.writeShort(salt.length);
                    out.write(salt);
                }
            } finally {
                out.flush();
            }
        }


        private static void writeKeyPair(KeyPair keyPair, DataOutputStream out) throws IOException {
            var encodedPublic = Utils.toUnsignedLittleEndian(((XECPublicKey) keyPair.getPublic()).getU(), 32);
            var encodedPrivate = ((XECPrivateKey) keyPair.getPrivate()).getScalar().orElseThrow();

            out.write(encodedPublic);
            out.write(encodedPrivate);
        }

        private static KeyPair readKeyPair(DataInputStream in) throws IOException {
            var encodedPk = in.readNBytes(32);
            var pk = decodePublicKey(encodedPk);

            var encodedSk = in.readNBytes(32);
            var sk = decodePrivateKey(encodedSk);

            return new KeyPair(pk, sk);
        }

        public static Optional<ConversationState> readFrom(InputStream inputStream) throws IOException {
            var in = new DataInputStream(new InflaterInputStream(inputStream, new Inflater(true)));
            var algorithmId = in.readUTF();
            if (!AUTHKEM_X25519_HKDF_A256SIV_HS256.getIdentifier().equals(algorithmId)) {
                return Optional.empty();
            }
            var application = in.readUTF();
            var privateKeys = readKeyPair(in);
            var salts = new LinkedHashMap<PublicKey, byte[]>();

            var numPks = in.readUnsignedShort();
            List<PublicKey> pks = new ArrayList<>(numPks);
            for (int i = 0; i < numPks; ++i) {
                var encoded = in.readNBytes(32);
                var pk = decodePublicKey(encoded);
                pks.add(pk);

                var saltLen = in.readUnsignedShort();
                var salt = in.readNBytes(saltLen);
                salts.put(pk, salt);
            }

            return Optional.of(new State(application, privateKeys, pks, salts::get));
        }

        @Override
        public void destroy() throws DestroyFailedException {
            if (demKey != null) {
                demKey.destroy();
            }
            if (ephemeralKeys != null) {
                ephemeralKeys.getPrivate().destroy();
            }
        }

        @Override
        public boolean isDestroyed() {
            return demKey != null && demKey.isDestroyed();
        }

        private static PublicKey decodePublicKey(byte[] keyMaterial) {
            try {
                var keyFactory = KeyFactory.getInstance("X25519");
                var pkUCoord = Utils.fromUnsignedLittleEndian(keyMaterial);
                return keyFactory.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, pkUCoord));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalArgumentException(e);
            }
        }

        private static PrivateKey decodePrivateKey(byte[] keyMaterial) {
            try {
                var keyFactory = KeyFactory.getInstance("X25519");
                return keyFactory.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, keyMaterial));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalArgumentException(e);
            }
        }

        Optional<byte[]> getKdfSaltFor(PublicKey publicKey) {
            return Optional.ofNullable(kdfSalt.apply(publicKey));
        }
    }
}
