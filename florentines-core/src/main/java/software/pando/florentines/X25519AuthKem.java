/*
 * Copyright 2022 Neil Madden.
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

package software.pando.florentines;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static software.pando.florentines.Utils.reverse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import software.pando.crypto.nacl.Bytes;
import software.pando.crypto.nacl.Crypto;
import software.pando.florentines.proto.X25519KemPreamble;
import software.pando.florentines.proto.X25519KemPreamble.RecipientBlob;

final class X25519AuthKem implements KEM {
    private static final Logger logger = LoggerFactory.getLogger(X25519AuthKem.class);

    private static final int EPK_LENGTH = 32;
    private static final int KID_LENGTH = 4;
    private static final int WRAPPED_KEY_LENGTH = 48;

    @Override
    public String getIdentifier() {
        return "AuthKEM-X25519";
    }

    @Override
    public KeyPair generateKeyPair() {
        return freshKeyPair();
    }

    @Override
    public EncapsulatedKey encapsulate(KeyInfo sender, Collection<KeyInfo> recipients, byte[] assocData) {
        validateLocalKey(sender);
        validateRemoteKeys(sender.getAlgorithm(), recipients);

        var demKey = Crypto.kdfKeyGen();
        var ephemeralKeys = freshKeyPair();
        var epk = ephemeralKeys.getPublic().getEncoded();
        byte[] salt = sender.getAlgorithm().getIdentifier().getBytes(UTF_8);

        var preambleBuilder = X25519KemPreamble.newBuilder()
                .setEpk(ByteString.copyFrom(epk))
                .setSenderKeyId(ByteString.copyFrom(sender.getKeyId(epk)));
        for (var recipient : recipients) {
            byte[] context = buildContext(sender, recipient, epk);
            byte[] wrappedKey = wrapDemKey(
                    sender.getAlgorithm().dem,
                    demKey,
                    sender.getSecretKey().orElseThrow(),
                    ephemeralKeys,
                    recipient.getPublicKey().orElseThrow(),
                    salt,
                    context,
                    assocData);
            var recipientBlob = RecipientBlob.newBuilder()
                    .setRecipientKeyId(ByteString.copyFrom(recipient.getKeyId(epk)))
                    .setWrappedKey(ByteString.copyFrom(wrappedKey))
                    .build();
            preambleBuilder.addRecipientBlob(recipientBlob);
        }

        return new EncapsulatedKey(demKey, preambleBuilder.build().toByteArray());
    }

    @Override
    public Optional<DecapsulatedKey> decapsulate(Collection<KeyInfo> recipientKeys, Collection<KeyInfo> possibleSenders,
            byte[] encapsulatedKey, byte[] assocData) {
        recipientKeys.forEach(this::validateLocalKey);

        try {
            var decodedPreamble = X25519KemPreamble.parseFrom(encapsulatedKey);
            var epk = decodedPreamble.getEpk().toByteArray();
            var senderSaltedKeyId = decodedPreamble.getSenderKeyId().toByteArray();

            if (epk.length != EPK_LENGTH) {
                throw new IllegalArgumentException("Invalid ephemeral public key in preamble");
            }
            if (senderSaltedKeyId.length != KID_LENGTH) {
                throw new IllegalArgumentException("Invalid sender key id in preamble");
            }

            var wrappedKeys = new TreeMap<byte[], byte[]>(Arrays::compareUnsigned);
            for (var recipientBlob : decodedPreamble.getRecipientBlobList()) {
                var recipientKeyId = recipientBlob.getRecipientKeyId().toByteArray();
                var keyBlob = recipientBlob.getWrappedKey().toByteArray();
                if (recipientKeyId.length != KID_LENGTH) {
                    throw new IllegalArgumentException("Invalid recipient key id in preamble");
                }
                if (keyBlob.length != WRAPPED_KEY_LENGTH) {
                    throw new IllegalArgumentException("Invalid wrapped key blob in preamble");
                }
                wrappedKeys.put(recipientKeyId, keyBlob);
            }

            for (var candidateSender : possibleSenders) {
                if (Bytes.equal(candidateSender.getKeyId(epk), senderSaltedKeyId)) {
                    logger.trace("Found matching sender key info: {}", candidateSender);

                    for (var candidateRecipient : recipientKeys) {
                        var wrappedKey = wrappedKeys.get(candidateRecipient.getKeyId(epk));
                        if (wrappedKey != null) {
                            logger.trace("Found matching local key info: {}", candidateRecipient);
                            var unwrappedKey = attemptDecryption(
                                    candidateSender,
                                    candidateRecipient,
                                    decodePublicKey(epk),
                                    wrappedKey,
                                    assocData);
                            if (unwrappedKey.isPresent()) {
                                logger.info("Key unwrapping succeeded");
                                return Optional.of(new DecapsulatedKey(unwrappedKey.get(), candidateSender));
                            }
                        }
                    }
                    logger.trace("Cannot decrypt key blob with any matching local keys - trying other candidate " +
                            "senders");
                }
            }

        } catch (InvalidProtocolBufferException e) {
            throw new IllegalArgumentException("Unable to read encapsulated key", e);
        }

        logger.trace("Unable to decrypt wrapped key blob for any known combination of sender/recipient keys");
        return Optional.empty();
    }

    private static Map<byte[], byte[]> readAllWrappedKeyBlobs(FieldInputStream in) throws IOException {
        Map<byte[], byte[]> blobs = new TreeMap<>(Arrays::compareUnsigned);
        int numRecipients = in.readLength();
        for (int i = 0; i < numRecipients; ++i) {
            var keyId = in.readNBytes(KID_LENGTH);
            var wrappedKey = in.readNBytes(WRAPPED_KEY_LENGTH);
            blobs.put(keyId, wrappedKey);
        }
        return blobs;
    }

    private static Optional<SecretKey> attemptDecryption(KeyInfo sender, KeyInfo recipient, PublicKey epk,
            byte[] wrappedKey, byte[] assocData) {
        byte[] ess = null, sss = null;
        SecretKey wrapKey = null;
        try {
            ess = x25519(recipient.getSecretKey().orElseThrow(), epk);
            sss = x25519(recipient.getSecretKey().orElseThrow(), sender.getPublicKey().orElseThrow());

            byte[] salt = sender.getAlgorithm().getIdentifier().getBytes(UTF_8);
            byte[] context = buildContext(sender, recipient, epk.getEncoded());
            var dem = sender.getAlgorithm().dem;

            byte[] keyMaterial = Crypto.kdfDeriveFromInputKeyMaterial(salt, Utils.concat(ess, sss), context, 32);
            wrapKey = dem.key(keyMaterial);
            Arrays.fill(keyMaterial, (byte) 0);

            byte[] payload = Arrays.copyOfRange(wrappedKey, 16, 48);
            byte[] siv = Arrays.copyOf(wrappedKey, 16);
            return dem.decrypt(wrapKey, siv, payload).andVerify(payload, assocData)
                    .map(chainKey -> dem.key(payload));

        } finally {
            if (ess != null) {
                Arrays.fill(ess, (byte) 0);
            }
            if (sss != null) {
                Arrays.fill(sss, (byte) 0);
            }
            Utils.destroy(wrapKey);
        }
    }

    private static byte[] buildContext(KeyInfo sender, KeyInfo recipient, byte[] epk) {
        var baos = new ByteArrayOutputStream();
        try (var out = new FieldOutputStream(baos)) {
            // AlgorithmID
            out.writeString(sender.getAlgorithm().getIdentifier());

            // PartyUInfo
            out.writeString(sender.getSubjectIdentifier());
            out.write(sender.getPublicKey().orElseThrow().getEncoded());

            // PartyVInfo
            out.writeString(recipient.getSubjectIdentifier());
            out.write(recipient.getPublicKey().orElseThrow().getEncoded());

            // SuppPubInfo - keydatalen (as a single byte), epk as 32 bytes
            out.write(32);
            out.write(epk);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
        return baos.toByteArray();
    }

    private static KeyPair freshKeyPair() {
        try {
            var kpg = KeyPairGenerator.getInstance("X25519");
            var keys = kpg.generateKeyPair();
            return new KeyPair(new X25519PublicKey((XECPublicKey) keys.getPublic()), keys.getPrivate());
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    private byte[] wrapDemKey(DEM dem, SecretKey demKey, Key senderKey, KeyPair ephemeralKeys, PublicKey recipientKey,
            byte[] salt, byte[] context, byte[] assocData) {
        byte[] ess = null, sss = null;
        SecretKey wrapKey = null;
        try {
            ess = x25519(ephemeralKeys.getPrivate(), recipientKey);
            sss = x25519(senderKey, recipientKey);

            byte[] keyMaterial = Crypto.kdfDeriveFromInputKeyMaterial(salt, Utils.concat(ess, sss), context, 32);
            wrapKey = dem.key(keyMaterial);
            Arrays.fill(keyMaterial, (byte) 0);

            byte[] payload = demKey.getEncoded();
            byte[] siv = dem.authenticate(wrapKey, payload, assocData).andEncrypt(payload);
            return Utils.concat(siv, payload);

        } finally {
            if (ess != null) {
                Arrays.fill(ess, (byte) 0);
            }
            if (sss != null) {
                Arrays.fill(sss, (byte) 0);
            }
            Utils.destroy(wrapKey);
        }
    }

    private static byte[] x25519(Key privateKey, PublicKey publicKey) {
        try {
            var x25519 = KeyAgreement.getInstance("X25519");
            x25519.init(privateKey);
            x25519.doPhase(publicKey, true);
            return x25519.generateSecret();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private void validateLocalKey(KeyInfo sender) {
        requireNonNull(sender, "Sender cannot be null");
        if (sender.getAlgorithm().kem != this) {
            throw new IllegalArgumentException("Key not intended for this algorithm");
        }
        Key secretKey = sender.getSecretKey().orElseThrow(() -> new IllegalArgumentException("Missing secret key"));
        if (!(secretKey instanceof XECPrivateKey)) {
            throw new IllegalArgumentException("Invalid sender key for algorithm");
        }
    }

    private void validateRemoteKeys(Algorithm algorithm, Collection<KeyInfo> recipients) {
        requireNonNull(recipients, "Recipients cannot be null");
        if (recipients.isEmpty()) {
            throw new IllegalArgumentException("No recipients specified");
        }
        if (recipients.size() >= 65536) {
            throw new IllegalArgumentException("Too many recipients (max: 65535)");
        }
        for (var recipient : recipients) {
            if (recipient.getAlgorithm() != algorithm) {
                throw new IllegalArgumentException("Algorithm mismatch");
            }
            PublicKey pk = recipient.getPublicKey()
                    .orElseThrow(() -> new IllegalArgumentException("Missing public key"));
            if (!(pk instanceof XECPublicKey)) {
                throw new IllegalArgumentException("Invalid recipient key for algorithm");
            }
        }
    }

    private static X25519PublicKey decodePublicKey(byte[] key) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("X25519");
            var u = new BigInteger(1, reverse(key));
            return new X25519PublicKey((XECPublicKey)
                    keyFactory.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    private static final class X25519PublicKey implements XECPublicKey {
        private final XECPublicKey publicKey;

        private X25519PublicKey(XECPublicKey publicKey) {
            this.publicKey = publicKey;
        }

        @Override
        public BigInteger getU() {
            return publicKey.getU();
        }

        @Override
        public String getAlgorithm() {
            return publicKey.getAlgorithm();
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return reverse(publicKey.getU().toByteArray());
        }

        @Override
        public AlgorithmParameterSpec getParams() {
            return publicKey.getParams();
        }
    }
}
