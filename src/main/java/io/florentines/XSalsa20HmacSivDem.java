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

import static io.florentines.Utils.allZero;
import static io.florentines.Utils.require;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static software.pando.crypto.nacl.Crypto.auth;
import static software.pando.crypto.nacl.Crypto.authKey;
import static software.pando.crypto.nacl.Crypto.kdfDeriveFromKey;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.slf4j.Logger;

import software.pando.crypto.nacl.ByteSlice;
import software.pando.crypto.nacl.Crypto;
import software.pando.crypto.nacl.Subtle;
import software.pando.crypto.nacl.Subtle.StreamCipher;

/**
 * A DEM implementation using a combination of the XSalsa20 stream cipher with HMAC-SHA-256 in a
 * <a href="https://datatracker.ietf.org/doc/html/rfc5297">Synthetic IV</a> (SIV)
 * construction. Rather than using the s2v construction with AES-CMAC, this DEM uses HMAC in a cascade construction
 * to process an arbitrary vector of inputs. The final tag at the end of the cascade becomes the caveat key for
 * appending further caveats, exactly matching the original Macaroon construction. A separate 128-bit SIV is produced
 * by applying HMAC again to the output of the cascade using an independent finalization key, with the result then
 * truncated to 128-bits. Validation of the SIV during decryption ensures authenticity of the initial vector of
 * inputs, and the finalization round prevents extension attacks on this initial vector, following the design of NMAC.
 * <p>
 * Arbitrary inputs from the initial input vector can optionally be encrypted using XSalsa20, with the SIV as
 * the pseudorandom nonce. If multiple inputs are to be encrypted then they are processed as if they were a single
 * input that was concatenated together. For example, if there are two inputs to encrypt: block A is 33 bytes and
 * block B is 14 bytes, then the XSalsa20 cipher is initialized with the encryption key and SIV and then 47 bytes
 * of key stream are produced and the first 33 bytes are XORed with block A (in-place) and then the remaining 14
 * bytes with block B. This ensures that all encrypted blocks achieve full misuse-resistant authenticated encryption
 * regardless of where they appear in the vector.
 * <p>
 * The use of HMAC-SHA-256 rather than CMAC is partly because HMAC is more widely implemented than CMAC, but mainly
 * because it ensures the authentication tag/SIV is compactly-committing, which is required to ensure insider
 * authentication security when used in combination with a KEM. The 256-bit initial key is expanded into 3 keys for
 * the HMAC cascade, XSalsa20, and HMAC finalization using HKDF-SHA-256. This is partly to avoid a large key input, but
 * also to ensure that the initial key can be used as an "opener" for the compactly committing ciphertext if somebody
 * wishes to build a message franking system on top of this, as per the original Grubbs et al paper.
 */
final class XSalsa20HmacSivDem implements DEM {
    private static final Logger logger = RedactedLogger.getLogger(XSalsa20HmacSivDem.class);
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String ENC_ALGORITHM = "XSalsa20";

    @Override
    public String getIdentifier() {
        return "XS20SIV-HS256";
    }

    @Override
    public SecretKey importKey(byte[] keyMaterial) {
        require(requireNonNull(keyMaterial).length == 32, "Key must be 32 bytes");
        require(!allZero(keyMaterial), "Key material has been zeroed");
        return authKey(keyMaterial);
    }

    @Override
    public MessageEncryptor beginEncryption(SecretKey demKey) {
        require(!requireNonNull(demKey).isDestroyed(), "Key has been destroyed");
        var subKeys = expandKey(demKey);
        return new Encryptor(subKeys[0], subKeys[1], subKeys[2]);
    }

    @Override
    public MessageDecryptor beginDecryption(SecretKey demKey, byte[] siv) {
        var subKeys = expandKey(demKey);
        return new Decryptor(subKeys[0], subKeys[1], subKeys[2], siv);
    }

    private SecretKey[] expandKey(SecretKey demKey) {
        require(!demKey.isDestroyed(), "Key has been destroyed");
        var expandedKey = kdfDeriveFromKey(demKey, getIdentifier().getBytes(UTF_8), 3 * 32);
        var macKey = Crypto.authKey(ByteSlice.of(expandedKey, 0, 32));
        var encKey = Subtle.streamXSalsa20Key(ByteSlice.of(expandedKey, 32, 32));
        var finKey = Crypto.authKey(ByteSlice.of(expandedKey, 64, 32));
        Utils.wipe(expandedKey);

        return new SecretKey[] { macKey, encKey, finKey };
    }

    private static abstract class MessageProcessor<T> {
        final SecretKey encKey;
        final SecretKey finKey;
        byte[] tag;

        MessageProcessor(SecretKey macKey, SecretKey encKey, SecretKey finKey) {
            this.tag = macKey.getEncoded();
            this.encKey = encKey;
            this.finKey = finKey;
            Utils.destroy(macKey);
        }

        abstract T self();

        public T authenticate(byte[] data) {
            var macKey = authKey(this.tag);
            this.tag = auth(macKey, requireNonNull(data));
            Utils.destroy(macKey);
            return self();
        }

        void destroy() {
            Utils.destroy(encKey);
            Utils.destroy(finKey);
            Utils.wipe(tag);
        }

        byte[] siv() {
            return Arrays.copyOf(auth(finKey, this.tag), 16);
        }

        byte[] nonce(byte[] siv) {
            return Arrays.copyOf(siv, Subtle.XSALSA20_NONCE_SIZE);
        }
    }

    private class Encryptor extends MessageProcessor<Encryptor> implements MessageEncryptor {
        private final List<byte[]> encryptedBlocks = new ArrayList<>();

        Encryptor(SecretKey macKey, SecretKey encKey, SecretKey finKey) {
            super(macKey, encKey, finKey);
        }

        @Override
        Encryptor self() {
            return this;
        }

        @Override
        public MessageEncryptor encryptAndAuthenticate(byte[] plaintext) {
            authenticate(plaintext);
            encryptedBlocks.add(plaintext);
            return this;
        }

        @Override
        public Pair<byte[], SecretKey> done() {
            var caveatKey = importKey(this.tag);
            var siv = siv();
            try (var cipher = Subtle.streamXSalsa20(encKey, nonce(siv))) {
                for (var block : encryptedBlocks) {
                    cipher.process(ByteSlice.of(block));
                }
                return Pair.of(siv, caveatKey);
            } finally {
                Utils.destroy(encKey);
                Utils.destroy(finKey);
                Utils.wipe(tag);
                encryptedBlocks.clear();
            }
        }
    }

    private class Decryptor extends MessageProcessor<Decryptor> implements MessageDecryptor {
        private final StreamCipher cipher;
        private final byte[] siv;

        Decryptor(SecretKey macKey, SecretKey encKey, SecretKey finKey,
                byte[] siv) {
            super(macKey, encKey, finKey);
            this.siv = siv.clone();
            this.cipher = Subtle.streamXSalsa20(encKey, nonce(siv));
        }

        @Override
        Decryptor self() {
            return this;
        }

        @Override
        public MessageDecryptor decryptAndAuthenticate(byte[] data) {
            cipher.process(ByteSlice.of(data));
            authenticate(data);
            return this;
        }

        @Override
        public Optional<SecretKey> verify() {
            try {
                var computedSiv = Arrays.copyOf(auth(finKey, this.tag), 16);
                logger.trace("SIV: computed={}, provided={}", computedSiv, siv);
                var caveatKey = importKey(this.tag);
                logger.trace("Caveat Key: {}", caveatKey);
                if (MessageDigest.isEqual(computedSiv, siv)) {
                    return Optional.of(caveatKey);
                }

                return Optional.empty();
            } finally {
                destroy();
            }
        }
    }
}
