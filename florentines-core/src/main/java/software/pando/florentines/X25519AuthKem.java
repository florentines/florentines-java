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
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Collection;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import software.pando.crypto.nacl.Crypto;

final class X25519AuthKem implements KEM {

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
        validateSender(sender);
        validateRecipients(sender.getAlgorithm(), recipients);

        var demKey = Crypto.kdfKeyGen();
        var ephemeralKeys = freshKeyPair();
        var epk = ephemeralKeys.getPublic().getEncoded();
        byte[] salt = sender.getAlgorithm().getIdentifier().getBytes(UTF_8);

        var baos = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(baos)) {
            assert epk.length == 32;
            out.write(epk);
            out.write(sender.getKeyId(epk));

            out.writeShort(recipients.size());
            for (var recipient : recipients) {
                out.write(recipient.getKeyId(epk));
                byte[] context = buildContext(sender, recipient);
                out.write(wrapDemKey(
                        sender.getAlgorithm().dem,
                        demKey,
                        sender.getSecretKey().orElseThrow(),
                        ephemeralKeys,
                        recipient.getPublicKey().orElseThrow(),
                        salt,
                        context,
                        assocData));
            }

        } catch (IOException e) {
            throw new AssertionError("Unexpected IOException", e);
        }

        return new EncapsulatedKey(demKey, baos.toByteArray());
    }

    private static byte[] buildContext(KeyInfo sender, KeyInfo recipient) {
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

            // SuppPubInfo - keydatalen (as a single byte).
            out.write(32);
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

    private void validateSender(KeyInfo sender) {
        requireNonNull(sender, "Sender cannot be null");
        if (sender.getAlgorithm().kem != this) {
            throw new IllegalArgumentException("Key not intended for this algorithm");
        }
        Key secretKey = sender.getSecretKey().orElseThrow(() -> new IllegalArgumentException("Missing secret key"));
        if (!(secretKey instanceof XECPrivateKey)) {
            throw new IllegalArgumentException("Invalid sender key for algorithm");
        }
    }

    private void validateRecipients(Algorithm algorithm, Collection<KeyInfo> recipients) {
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
