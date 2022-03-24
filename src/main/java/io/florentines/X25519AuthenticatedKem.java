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
import static io.florentines.Utils.require;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static java.util.function.Predicate.not;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.slf4j.Logger;


final class X25519AuthenticatedKem implements KEM {
    private static final Logger logger = RedactedLogger.getLogger(X25519AuthenticatedKem.class);
    private static final int SALTED_KEYID_LENGTH = 4;
    private static final int PUBLIC_KEY_LENGTH = 32;
    private static final int WRAPPED_KEY_LENGTH = 48;

    private static final KeyPairGenerator keyPairGenerator;
    private static final KeyFactory keyFactory;

    static {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("X25519");
            keyFactory = KeyFactory.getInstance("X25519");
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
        synchronized (keyPairGenerator) {
            keyPair = keyPairGenerator.generateKeyPair();
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
        var salt = Crypto.hash(("Florentine-" + getIdentifier()).getBytes(UTF_8));
        return internalBegin(localParty.getPublicIdentity().getApplication(), localParty, List.of(remoteParties),
                any -> salt.clone());
    }

    private State internalBegin(String application, PrivateIdentity privateKeys, List<PublicIdentity> publicKeys,
            Function<PublicIdentity, byte[]> salt) {
        logger.trace("Initialising state: app={}, localKeys={}, remoteKeys={}", application, privateKeys, publicKeys);
        if (logger.isTraceEnabled()) {
            for (var pk : publicKeys) {
                logger.trace("Salt for key <{}> = {}", pk, salt.apply(pk));
            }
        }
        return new State(application, privateKeys, publicKeys, salt);
    }

    @Override
    public DestroyableSecretKey demKey(ConversationState state) {
        return validateState(state).getDemKey();
    }

    @Override
    public Pair<ConversationState, EncapsulatedKey> authEncap(ConversationState stateArg, byte[] tag) {
        var state = validateState(stateArg);
        require("RAW".equalsIgnoreCase(state.getDemKey().getFormat()), "DEM key is not RAW format");
        var encodedDemKey = state.getDemKey().getEncoded();

        var salts = new LinkedHashMap<PublicIdentity, byte[]>();
        var wrappedKeys = new LinkedHashMap<PublicIdentity, byte[]>(state.remoteKeys.size());

        for (var recipient : state.remoteKeys) {
            var salt = state.getKdfSaltFor(recipient)
                    .orElseThrow(() -> new IllegalStateException("Unable to determine KDF salt for recipient"));
            var recipientPk = decodePublicKey(recipient);
            var context = kdfContext(state.application, state.localKeys.getPublicIdentity(), recipient,
                    state.getEphemeralKeys().getPublicIdentity());
            var keys = keyAgreement(state.getEphemeralKeys().getSecretKey(), recipientPk,
                    state.localKeys.getSecretKey(), recipientPk, salt, context);

            var wrapKey = keys.getFirst();
            var chainingKey = keys.getSecond();
            salts.put(recipient, chainingKey);

            try {
                var wrapped = wrap(wrapKey, encodedDemKey, tag);
                wrappedKeys.put(recipient, wrapped);
            } finally {
                wrapKey.destroy();
            }
        }

        var encapKey = new EncapKey(state.ephemeralKeys.getPublicIdentity(), state.localKeys.getPublicIdentity(),
                wrappedKeys);
        logger.trace("Creating state to decrypt any replies");
        var newState = internalBegin(state.application, state.getEphemeralKeys(), state.remoteKeys, salts::get);
        return Pair.of(newState, encapKey);
    }

    private byte[] kdfContext(String application, PublicIdentity sender, PublicIdentity recipient, PublicIdentity epk) {
        var baos = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(baos)) {
            out.writeUTF(getIdentifier());
            out.writeUTF(application);
            out.writeUTF(sender.getId());
            out.writeUTF(recipient.getId());
            out.write(sender.getPublicKeyMaterial());
            out.write(recipient.getPublicKeyMaterial());
            out.write(epk.getPublicKeyMaterial());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return baos.toByteArray();
    }

    @Override
    public Optional<Pair<ConversationState, DestroyableSecretKey>> authDecap(ConversationState stateArg,
            byte[] encapKey, byte[] tag) {
        var state = validateState(stateArg);
        var keyDataOptional = EncapKey.fromBytes(encapKey, state.remoteKeys,
                List.of(state.localKeys.getPublicIdentity()));
        if (keyDataOptional.isEmpty()) {
            return Optional.empty();
        }
        var keyData = keyDataOptional.orElseThrow();
        if (keyData.recipientBlobs.isEmpty()) {
            return Optional.empty();
        }

        var wrappedKey = keyData.recipientBlobs.get(state.localKeys.getPublicIdentity());
        if (wrappedKey == null) {
            logger.debug("No wrapped key blob matches local key");
            return Optional.empty();
        }
        var salt = state.getKdfSaltFor(keyData.senderPublicKey);
        if (salt.isEmpty()) {
            logger.debug("No KDF salt for local key");
            return Optional.empty();
        }
        var context = kdfContext(state.application, keyData.senderPublicKey, state.localKeys.getPublicIdentity(),
                keyData.ephemeralPublicKey);
        var keys = keyAgreement(state.localKeys.getSecretKey(),
                decodePublicKey(keyData.ephemeralPublicKey),
                state.localKeys.getSecretKey(),
                decodePublicKey(keyData.senderPublicKey), salt.orElseThrow(),
                context);

        var wrapKey = keys.getFirst();
        var chainingKey = keys.getSecond();
        try {
            var unwrapped = unwrap(wrapKey, wrappedKey, tag);
            // Key IDs are only 4 bytes, so a matching Key ID doesn't guarantee that it is for us -
            // if unwrapping fails, then continue trying other wrapped key blobs
            return unwrapped.map(demKey -> {
                logger.trace("Creating state for sending any reply");
                var newState = internalBegin(state.application, state.localKeys, List.of(keyData.ephemeralPublicKey),
                        any -> chainingKey);
                return Pair.of(newState, demKey);
            });
        } finally {
            wrapKey.destroy();
        }
    }

    private Pair<DestroyableSecretKey, byte[]> keyAgreement(Key sk1, PublicKey pk1, Key sk2, PublicKey pk2,
            byte[] salt, byte[] context) {
        byte[] ephemeralStatic = null, staticStatic = null, outputKeyMaterial = null;
        DestroyableSecretKey sharedSecret = null;

        logger.trace("KDF salt: {}, context: {}", salt, context);

        try {
            ephemeralStatic = Crypto.x25519(sk1, pk1);
            staticStatic = Crypto.x25519(sk2, pk2);
            sharedSecret = HKDF.extract(ephemeralStatic, staticStatic, salt);
            outputKeyMaterial = HKDF.expand(sharedSecret, context, 64);
            var wrapKey = dem.importKey(Arrays.copyOf(outputKeyMaterial, 32));
            var chainingKey = Arrays.copyOfRange(outputKeyMaterial, 32, 64);

            if (logger.isTraceEnabled()) {
                logger.trace("Key agreement: es={}, ss={}, sharedSecret={}, okm={}",
                        ephemeralStatic, staticStatic, sharedSecret, outputKeyMaterial);
            }

            return Pair.of(wrapKey, chainingKey);
        } finally {
            Utils.wipe(ephemeralStatic, staticStatic, outputKeyMaterial);
            if (sharedSecret != null) { sharedSecret.destroy(); }
        }
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

    private static PublicKey decodePublicKey(PublicIdentity publicKey) {
        return decodePublicKey(publicKey.getPublicKeyMaterial());
    }

    private static PublicKey decodePublicKey(byte[] encoded) {
        var decodedPubKey = Utils.fromUnsignedLittleEndian(encoded);
        synchronized (keyFactory) {
            try {
                return keyFactory.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, decodedPubKey));
            } catch (InvalidKeySpecException e) {
                throw new IllegalArgumentException("Invalid public key", e);
            }
        }
    }

    private static byte[] saltedKeyId(byte[] salt, PublicIdentity pk) {
        return Arrays.copyOf(HKDF.extract(pk.getPublicKeyMaterial(), salt).getEncoded(), SALTED_KEYID_LENGTH);
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
        require(stateArg instanceof State, "Invalid state object");
        return (State) stateArg;
    }

    static final class State implements ConversationState {
        final String application;
        final PrivateIdentity localKeys;
        final List<PublicIdentity> remoteKeys;
        private final Function<PublicIdentity, byte[]> kdfSalt;

        private PrivateIdentity ephemeralKeys;
        private DestroyableSecretKey demKey;

        State(String application, PrivateIdentity localParty, List<PublicIdentity> remoteParties,
                Function<PublicIdentity, byte[]> kdfSalt) {
            this.application = requireNonNull(application, "application");
            this.localKeys = requireNonNull(localParty, "local keys");
            this.remoteKeys = requireNonNull(remoteParties, "remote keys");
            this.kdfSalt = requireNonNull(kdfSalt, "KDF salt function");

            if (remoteParties.isEmpty() || remoteParties.size() > 65535) {
                throw new IllegalArgumentException("Must be at least 1 and at most 65535 public keys");
            }
        }

        PrivateIdentity getEphemeralKeys() {
            if (ephemeralKeys == null) {
                ephemeralKeys = AUTHKEM_X25519_HKDF_A256SIV_HS256.generateKeys(
                        localKeys.getPublicIdentity().getApplication(), localKeys.getPublicIdentity().getId());
            }
            return ephemeralKeys;
        }

        DestroyableSecretKey getDemKey() {
            if (demKey == null) {
                // In principle we could just generate an entirely random fresh DEM key here. However, we are aiming
                // that our unified KEM-DEM construction should provide misuse-resistant authenticated encryption. We
                // want to ensure that failures of randomness generation (at runtime) do not result in catastrophic
                // loss of security. However, if our randomness fails when generating the DEM key, such that the key
                // becomes predictable to an attacker, then it's likely that all security will be lost. To hedge
                // against that possibility, we pseudorandomly generate the DEM key using our local private key as an
                // additional source of entropy. That way, even if the entropy of the salt generation fails
                // completely such that the attacker can completely predict it, they will not be able to predict the
                // DEM key itself and the MRAE (DAE) security of the DEM will prevent a catastrophic failure.
                var salt = Crypto.randomBytes(32);
                var priv = ((XECPrivateKey) localKeys.getSecretKey()).getScalar().orElseThrow();
                try {
                    demKey = HKDF.extract(priv, salt);
                } finally {
                    Utils.wipe(priv, salt);
                }
            }
            return demKey;
        }

        @Override
        public void writeTo(OutputStream outputStream) throws IOException {
            var out = new DataOutputStream(new DeflaterOutputStream(outputStream, new Deflater(Deflater.DEFLATED, true)));
            try {
                out.writeUTF(AUTHKEM_X25519_HKDF_A256SIV_HS256.getIdentifier());
                out.writeUTF(application);
                writeLocalParty(localKeys, out);
                out.writeShort(remoteKeys.size());
                for (var pk : remoteKeys) {
                    out.writeUTF(pk.getId());
                    out.write(pk.getPublicKeyMaterial());
                    var salt = kdfSalt.apply(pk);
                    out.writeShort(salt.length);
                    out.write(salt);
                }
            } finally {
                out.flush();
            }
        }

        private static void writeLocalParty(PrivateIdentity identity, DataOutputStream out) throws IOException {
            var encodedPrivate = identity.getSecretKeyAs(XECPrivateKey.class)
                    .flatMap(XECPrivateKey::getScalar)
                    .orElseThrow();
            out.writeUTF(identity.getPublicIdentity().getId());
            out.write(identity.getPublicIdentity().getPublicKeyMaterial());
            out.write(encodedPrivate);
        }

        private static PrivateIdentity readLocalParty(DataInputStream in, String application) throws IOException {
            var id = in.readUTF();
            var encodedPk = in.readNBytes(32);

            var publicIdentity = new PublicIdentity(encodedPk, AUTHKEM_X25519_HKDF_A256SIV_HS256.getIdentifier(),
                    application, id);

            var encodedSk = in.readNBytes(32);
            var sk = decodePrivateKey(encodedSk);

            return new PrivateIdentity(sk, publicIdentity);
        }

        public static Optional<ConversationState> readFrom(InputStream inputStream) throws IOException {
            var in = new DataInputStream(new InflaterInputStream(inputStream, new Inflater(true)));
            var algorithmId = in.readUTF();
            if (!AUTHKEM_X25519_HKDF_A256SIV_HS256.getIdentifier().equals(algorithmId)) {
                return Optional.empty();
            }
            var application = in.readUTF();
            var privateKeys = readLocalParty(in, application);
            var salts = new LinkedHashMap<PublicIdentity, byte[]>();

            var numPks = in.readUnsignedShort();
            List<PublicIdentity> pks = new ArrayList<>(numPks);
            for (int i = 0; i < numPks; ++i) {
                var id = in.readUTF();
                var encoded = in.readNBytes(32);
                var identity = new PublicIdentity(encoded, algorithmId, application, id);
                pks.add(identity);

                var saltLen = in.readUnsignedShort();
                var salt = in.readNBytes(saltLen);
                salts.put(identity, salt);
            }

            return Optional.of(new State(application, privateKeys, pks, salts::get));
        }

        @Override
        public void destroy() throws DestroyFailedException {
            if (demKey != null) {
                demKey.destroy();
            }
            if (ephemeralKeys != null && ephemeralKeys.getSecretKey() instanceof Destroyable) {
                ((Destroyable) ephemeralKeys.getSecretKey()).destroy();
            }
        }

        @Override
        public boolean isDestroyed() {
            return demKey != null && demKey.isDestroyed();
        }

        private static PrivateKey decodePrivateKey(byte[] keyMaterial) {
            try {
                var keyFactory = KeyFactory.getInstance("X25519");
                return keyFactory.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, keyMaterial));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalArgumentException(e);
            }
        }

        Optional<byte[]> getKdfSaltFor(PublicIdentity identity) {
            return Optional.ofNullable(kdfSalt.apply(identity));
        }
    }

    private static class EncapKey implements EncapsulatedKey {
        final PublicIdentity ephemeralPublicKey;
        final PublicIdentity senderPublicKey;
        final Map<PublicIdentity, byte[]> recipientBlobs;

        private EncapKey(PublicIdentity ephemeralPublicKey, PublicIdentity senderPublicKey,
                Map<PublicIdentity, byte[]> recipientBlobs) {
            this.ephemeralPublicKey = ephemeralPublicKey;
            this.senderPublicKey = senderPublicKey;
            this.recipientBlobs = recipientBlobs;
        }

        @Override
        public void writeTo(OutputStream outputStream) throws IOException {
            var out = new DataOutputStream(outputStream);

            var epk = ephemeralPublicKey.getPublicKeyMaterial();
            out.write(epk);
            out.write(saltedKeyId(epk, senderPublicKey));

            out.writeShort(recipientBlobs.size());
            for (var entry : recipientBlobs.entrySet()) {
                out.write(saltedKeyId(epk, entry.getKey()));
                out.write(entry.getValue());
            }
        }

        static Optional<EncapKey> readFrom(InputStream inputStream, List<PublicIdentity> candidateSenderKeys,
                List<PublicIdentity> candidateRecipientKeys) throws IOException {
            var in = new DataInputStream(inputStream);
            var epk = in.readNBytes(PUBLIC_KEY_LENGTH);
            var saltedSenderKeyId = in.readNBytes(SALTED_KEYID_LENGTH);
            var senderKey = matchPublicKey(epk, saltedSenderKeyId, candidateSenderKeys);

            var numRecipients = in.readUnsignedShort();
            var recipientBlobs = new LinkedHashMap<PublicIdentity, byte[]>(numRecipients);
            for (int i = 0; i < numRecipients; ++i) {
                var recipientKeyId = in.readNBytes(SALTED_KEYID_LENGTH);
                var wrappedKey = in.readNBytes(WRAPPED_KEY_LENGTH);
                var recipientKey = matchPublicKey(epk, recipientKeyId, candidateRecipientKeys);
                if (recipientKey != null) {
                    recipientBlobs.put(recipientKey, wrappedKey);
                }
            }

            if (senderKey == null) {
                return Optional.empty();
            }
            var ephemeralIdentity = new PublicIdentity(epk, senderKey.getAlgorithmIdentifier(),
                    senderKey.getApplication(), senderKey.getId());

            return Optional.of(new EncapKey(ephemeralIdentity, senderKey, recipientBlobs));
        }

        static Optional<EncapKey> fromBytes(byte[] encapKey, List<PublicIdentity> candidateSenderKeys,
                List<PublicIdentity> candidateRecipientKeys) {
            try (var in = new ByteArrayInputStream(encapKey)) {
                return readFrom(in, candidateSenderKeys,  candidateRecipientKeys);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        private static PublicIdentity matchPublicKey(byte[] salt, byte[] saltedKeyId, List<PublicIdentity> candidates) {
            for (var candidate : candidates) {
                var expectedKeyId = saltedKeyId(salt, candidate);
                if (Arrays.equals(expectedKeyId, saltedKeyId)) {
                    return candidate;
                }
            }
            return null;
        }
    }
}
