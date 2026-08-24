/*
 * Copyright 2026 Neil Madden.
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

package io.florentines;

import javax.crypto.KeyAgreement;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.SequencedMap;

import static java.nio.charset.StandardCharsets.*;

/**
 * An authenticated Key Encapsulation Mechanism (KEM).
 */
public interface AuthKEM {
    String identifier();
    KeyPair generateKeyPair();
    EncapsulationResult encapsulate(String dem, KeyPair sender, List<PublicKey> recipients);
    DestroyableSecretKey decapsulate(String dem, KeyPair recipient, PublicKey sender, byte[] encapsulatedKey);
    record EncapsulationResult(byte[] encapsulatedKey, SequencedMap<PublicKey, DestroyableSecretKey> keys) {}

    final class X25519KEM implements AuthKEM {
        @Override
        public String identifier() {
            return "AuthKEM-X25519";
        }

        @Override
        public EncapsulationResult encapsulate(String dem, KeyPair sender, List<PublicKey> recipients) {
            var keys = new LinkedHashMap<PublicKey, DestroyableSecretKey>(recipients.size());
            var salt = kdfSalt(dem);
            var ephemeral = generateKeyPair();

            var sharedSecret = new byte[32];
            for (var recipient : recipients) {
                var staticStatic = x25519(sender.getPrivate(), recipient);
                var ephemeralStatic = x25519(ephemeral.getPrivate(), recipient);
                var kdfContext = kdfContext(sender.getPublic(), ephemeral.getPublic(), recipient);

                CryptoUtils.hkdf(salt, kdfContext, staticStatic, ephemeralStatic, sharedSecret);
                keys.put(recipient, new DestroyableSecretKey(dem, sharedSecret));
                Arrays.fill(sharedSecret, (byte) 0);
            }

            return new EncapsulationResult(serialize(ephemeral.getPublic()), keys);
        }

        @Override
        public DestroyableSecretKey decapsulate(String dem, KeyPair recipient, PublicKey sender, byte[] encapsulatedKey) {
            var salt = kdfSalt(dem);
            var epk = deserialize(encapsulatedKey);
            var kdfContext = kdfContext(sender, epk, recipient.getPublic());

            var staticStatic = x25519(recipient.getPrivate(), sender);
            var ephemeralStatic = x25519(recipient.getPrivate(), epk);
            var sharedSecret = new byte[32];
            try {
                CryptoUtils.hkdf(salt, kdfContext, staticStatic, ephemeralStatic, sharedSecret);
                return new DestroyableSecretKey(dem, sharedSecret);
            } finally {
                Arrays.fill(sharedSecret, (byte) 0);
            }
        }

        private static byte[] kdfSalt(String dem) {
            return ("Florentine-AuthKEM-X25519-" + dem).getBytes(UTF_8);
        }

        static byte[] kdfContext(PublicKey senderPk, PublicKey ephemeralPk, PublicKey recipientPk) {
            var kdfContext = new ByteArrayOutputStream();
            kdfContext.writeBytes(serialize(senderPk));
            kdfContext.writeBytes(serialize(recipientPk));
            kdfContext.writeBytes(serialize(ephemeralPk));
            return kdfContext.toByteArray();
        }

        static byte[] serialize(PublicKey pk) {
            if (!(pk instanceof XECPublicKey xpk) ||
                    !"X25519".equals(((NamedParameterSpec) xpk.getParams()).getName())) {
                throw new IllegalArgumentException("invalid public key");
            }
            var littleEndian = Utils.reverseInPlace(xpk.getU().toByteArray());
            return littleEndian.length == 32 ? littleEndian : Arrays.copyOf(littleEndian, 32); // Pad with zero bytes
        }

        static PublicKey deserialize(byte[] epk) {
            if (epk == null || epk.length != 32) {
                throw new IllegalArgumentException("invalid encapsulated key");
            }
            var u = new BigInteger(1, Utils.reverseInPlace(epk));
            try {
                var kf = KeyFactory.getInstance("X25519");
                return kf.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public KeyPair generateKeyPair() {
            try {
                var keyGen = KeyPairGenerator.getInstance("X25519");
                return keyGen.generateKeyPair();
            } catch (NoSuchAlgorithmException e) {
                throw new AssertionError(e);
            }
        }

        static byte[] x25519(PrivateKey privateKey, PublicKey publicKey) {
            try {
                var dh = KeyAgreement.getInstance("X25519");
                dh.init(privateKey);
                dh.doPhase(publicKey, true);
                return dh.generateSecret();
            } catch (NoSuchAlgorithmException e) {
                throw new AssertionError(e);
            } catch (InvalidKeyException e) {
                throw new IllegalArgumentException(e);
            }
        }
    }
}
