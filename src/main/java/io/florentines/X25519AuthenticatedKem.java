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

import static java.util.Objects.requireNonNull;
import static java.util.function.Predicate.not;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
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
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.crypto.KeyAgreement;


final class X25519AuthenticatedKem implements KEM<XECPrivateKey> {

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
    private final byte[] salt;

    X25519AuthenticatedKem(DEM dem, byte[] salt) {
        this.dem = dem;
        this.salt = salt;
    }

    @Override
    public String getIdentifier() {
        return "AuthKEM-X25519-HKDF-" + dem.getIdentifier();
    }

    @Override
    public FlorentineSecretKey<XECPrivateKey> generateKeys(String application) {
        KeyPair keyPair;
        synchronized (KEY_PAIR_GENERATOR) {
            keyPair = KEY_PAIR_GENERATOR.generateKeyPair();
        }
        var encodedPubKey = Utils.toUnsignedLittleEndian(((XECPublicKey) keyPair.getPublic()).getU());
        var pubKey = new FlorentinePublicKey(encodedPubKey, getIdentifier(), application);
        return new FlorentineSecretKey<>((XECPrivateKey) keyPair.getPrivate(), XECPrivateKey::getScalar, pubKey);
    }

    @Override
    public byte[] authEncapsulate(FlorentineSecretKey<XECPrivateKey> senderKeys, List<FlorentinePublicKey> recipients,
            DestroyableSecretKey demKey, byte[] demTag) {
        validateKeys(senderKeys, recipients);
        var ephemeralKeys = generateKeys(senderKeys.getPublicKey().getApplicationContextString());
        var senderKeyPair = decodePrivateKey(senderKeys);
        var encodedEpk = ephemeralKeys.getPublicKey().getPublicKeyMaterial();

        var encodedDemKey = demKey.getEncoded();
        var baos = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(baos)) {

            out.write(encodedEpk); // 32 bytes
            out.writeShort(recipients.size()); // 2 bytes

            for (var recipient : recipients) {
                var recipientPk = decodePublicKey(recipient);
                var keyId = saltedKeyId(encodedEpk, recipient);

                var ephemeralStatic = x25519(ephemeralKeys.getSecretKey(), recipientPk);
                var staticStatic = x25519(senderKeyPair.getPrivate(), recipientPk);
                var sharedSecret = dem.importKey(HKDF.extract(ephemeralStatic, staticStatic, salt));
                var wrapped = wrap(sharedSecret, encodedDemKey, demTag);
                out.write(keyId); // 4 bytes
                out.write(wrapped); // 48 bytes
            }

        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return baos.toByteArray();
    }

    @Override
    public Optional<DestroyableSecretKey> authDecapsulate(FlorentineSecretKey<XECPrivateKey> recipientKeys,
            FlorentinePublicKey sender, byte[] demTag, byte[] encapsulatedKey) {

        try (var in = new DataInputStream(new ByteArrayInputStream(encapsulatedKey))) {

            var encodedEpk = in.readNBytes(32);
            var epk = decodePublicKey(encodedEpk);
            var expectedKeyId = saltedKeyId(encodedEpk, recipientKeys.getPublicKey());
            var senderPk = decodePublicKey(sender);

            var ephemeralStatic = x25519(recipientKeys.getSecretKey(), epk);
            var staticStatic = x25519(recipientKeys.getSecretKey(), senderPk);
            var sharedSecret = dem.importKey(HKDF.extract(ephemeralStatic, staticStatic, salt));

            var numRecipients = in.readUnsignedShort();
            for (int i = 0; i < numRecipients; ++i) {
                var keyId = in.readNBytes(4);
                var wrappedKey = in.readNBytes(48);

                if (MessageDigest.isEqual(expectedKeyId, keyId)) {
                    var unwrapped = unwrap(sharedSecret, wrappedKey, demTag);
                    // Key IDs are only 4 bytes, so a matching Key ID doesn't guarantee that it is for us - if
                    // decryption fails, then continue trying other wrapped key blobs
                    if (unwrapped.isPresent()) {
                        return unwrapped;
                    }
                }
            }

        } catch (IOException e) {
            return Optional.empty();
        }

        return Optional.empty();
    }

    private void validateKeys(FlorentineSecretKey<XECPrivateKey> privateKey, List<FlorentinePublicKey> publicKeys) {
        requireNonNull(privateKey, "Private key");
        requireNonNull(publicKeys, "Public key list");
        if (publicKeys.isEmpty()) {
            throw new IllegalArgumentException("No public keys provided");
        }
        if (publicKeys.size() > 65535) {
            throw new IllegalArgumentException("Too many public keys");
        }
        var expectedAlgorithm = getIdentifier();
        if (!expectedAlgorithm.equals(privateKey.getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException("Private key not intended for this algorithm");
        }
        if (publicKeys.stream().map(FlorentinePublicKey::getAlgorithm).anyMatch(not(expectedAlgorithm::equals))) {
            throw new IllegalArgumentException("At least one public key is for a different algorithm");
        }
        var expectedApplication = privateKey.getPublicKey().getApplicationContextString();
        if (publicKeys.stream().map(FlorentinePublicKey::getApplicationContextString)
                .anyMatch(not(expectedApplication::equals))) {
            throw new IllegalArgumentException("At least one public key is for a different application");
        }
    }

    private static KeyPair decodePrivateKey(FlorentineSecretKey<XECPrivateKey> secretKey) {
        var privateKey = secretKey.getSecretKey();
        var publicKey = decodePublicKey(secretKey.getPublicKey());
        return new KeyPair(publicKey, privateKey);
    }

    private static PublicKey decodePublicKey(FlorentinePublicKey publicKey) {
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

    private static byte[] saltedKeyId(byte[] salt, FlorentinePublicKey pk) {
        return Arrays.copyOf(HKDF.extract(pk.getPublicKeyMaterial(), salt), 4);
    }

    private byte[] wrap(DestroyableSecretKey wrapKey, byte[] encodedDemKey, byte[] demTag) {
        byte[] encrypted = encodedDemKey.clone();
        byte[] siv = new byte[16];
        dem.begin(wrapKey, siv).authenticate(demTag).encrypt(encrypted);
        return Utils.concat(siv, encrypted);
    }

    private Optional<DestroyableSecretKey> unwrap(DestroyableSecretKey wrapKey, byte[] wrappedKey, byte[] demTag) {
        var siv = Arrays.copyOf(wrappedKey, 16);
        var encrypted = Arrays.copyOfRange(wrappedKey, 16, wrappedKey.length);
        return dem.begin(wrapKey, siv).authenticate(demTag).decrypt(encrypted).map(ignored -> dem.importKey(encrypted));
    }
}
