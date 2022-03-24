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

import static io.florentines.Crypto.hmac;
import static io.florentines.Crypto.hmacKey;
import static io.florentines.Utils.allZero;
import static io.florentines.Utils.require;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.slf4j.Logger;

/**
 * A DEM implementation using a combination of AES in CTR mode with HMAC-SHA-256 in a
 * <a href="https://datatracker.ietf.org/doc/html/rfc5297">Synthetic IV</a> (SIV)
 * construction. Rather than using the s2v construction with AES-CMAC, this DEM uses HMAC in a cascade construction
 * to process an arbitrary vector of inputs. The final tag at the end of the cascade becomes the caveat key for
 * appending further caveats, exactly matching the original Macaroon construction. A separate 128-bit SIV is produced
 * by applying HMAC again to the output of the cascade using an independent finalization key, with the result then
 * truncated to 128-bits. Validation of the SIV during decryption ensures authenticity of the initial vector of
 * inputs, and the finalization round prevents extension attacks on this initial vector, following the design of NMAC.
 * <p>
 * Arbitrary inputs from the initial input vector can optionally be encrypted using AES in CTR mode, with the SIV as
 * the pseudorandom nonce. If multiple inputs are to be encrypted then they are processed as if they were a single
 * input that was concatenated together. For example, if there are two inputs to encrypt: block A is 33 bytes and
 * block B is 14 bytes, then the AES cipher in CTR mode is initialized with the encryption key and SIV (with the 31st
 * and 63rd bits cleared beforehand as per https://datatracker.ietf.org/doc/html/rfc5297#section-2.5) and then 47 bytes
 * of key stream are produced and the first 33 bytes are XORed with block A (in-place) and then the remaining 14
 * bytes with block B. This ensures that all encrypted blocks achieve full misuse-resistant authenticated encryption
 * regardless of where they appear in the vector.
 * <p>
 * The use of HMAC-SHA-256 rather than CMAC is partly because HMAC is more widely implemented than CMAC, but mainly
 * because it ensures the authentication tag/SIV is compactly-committing, which is required to ensure insider
 * authentication security when used in combination with a KEM. The 256-bit initial key is expanded into 3 keys for
 * the HMAC cascade, AES, and HMAC finalization using HKDF-SHA-256. This is partly to avoid a large key input, but
 * also to ensure that the initial key can be used as an "opener" for the compactly committing ciphertext if somebody
 * wishes to build a message franking system on top of this, as per the original Grubbs et al paper.
 */
final class AesHmacSivDem implements DEM {
    private static final Logger logger = RedactedLogger.getLogger(AesHmacSivDem.class);
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String ENC_ALGORITHM = "AES/CTR/NoPadding";

    private static final ThreadLocal<Cipher> CIPHER_THREAD_LOCAL =
            ThreadLocal.withInitial(() -> {
                try {
                    return Cipher.getInstance(ENC_ALGORITHM);
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new AssertionError("JVM doesn't support AES/CTR encryption", e);
                }
            });

    @Override
    public String getIdentifier() {
        return "A256SIV-HS256";
    }

    @Override
    public DestroyableSecretKey importKey(byte[] keyMaterial) {
        require(requireNonNull(keyMaterial).length == 32, "Key must be 32 bytes");
        require(!allZero(keyMaterial), "Key material has been zeroed");
        return hmacKey(keyMaterial);
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

    private DestroyableSecretKey[] expandKey(SecretKey demKey) {
        require(!demKey.isDestroyed(), "Key has been destroyed");
        var expandedKey = HKDF.expand(demKey, getIdentifier().getBytes(UTF_8), 3*32);
        var macKey = new DestroyableSecretKey(MAC_ALGORITHM, expandedKey, 0, 32);
        var encKey = new DestroyableSecretKey("AES", expandedKey, 32, 32);
        var finKey = new DestroyableSecretKey(MAC_ALGORITHM, expandedKey, 64, 32);
        Utils.wipe(expandedKey);

        return new DestroyableSecretKey[] { macKey, encKey, finKey };
    }

    private static abstract class MessageProcessor<T> {
        final DestroyableSecretKey encKey;
        final DestroyableSecretKey finKey;
        byte[] tag;

        MessageProcessor(DestroyableSecretKey macKey, DestroyableSecretKey encKey, DestroyableSecretKey finKey) {
            this.tag = macKey.getEncoded();
            this.encKey = encKey;
            this.finKey = finKey;
            macKey.destroy();
        }

        abstract T self();

        public T authenticate(byte[] data) {
            var macKey = hmacKey(this.tag);
            this.tag = hmac(macKey, requireNonNull(data));
            macKey.destroy();
            return self();
        }

        Cipher getCipher(int mode, byte[] siv) {
            var cipher = CIPHER_THREAD_LOCAL.get();
            siv = siv.clone();
            siv[8] &= 0x7F;
            siv[12] &= 0x7F;
            try {
                cipher.init(mode, encKey, new IvParameterSpec(siv));
                return cipher;
            } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
                throw new IllegalArgumentException(e);
            }
        }

        void destroy() {
            encKey.destroy();
            finKey.destroy();
            Utils.wipe(tag);
        }
    }

    private class Encryptor extends MessageProcessor<Encryptor> implements MessageEncryptor {
        private final List<byte[]> encryptedBlocks = new ArrayList<>();

        Encryptor(DestroyableSecretKey macKey, DestroyableSecretKey encKey, DestroyableSecretKey finKey) {
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
        public Pair<byte[], DestroyableSecretKey> done() {
            var siv = Arrays.copyOf(hmac(finKey, this.tag), 16);
            var caveatKey = importKey(this.tag);
            var cipher = getCipher(Cipher.ENCRYPT_MODE, siv);
            try {
                for (var block : encryptedBlocks) {
                    int numBytes = cipher.update(block, 0, block.length, block);
                    assert numBytes == block.length;
                }

                byte[] leftOver = cipher.doFinal();
                assert leftOver.length == 0;

                return Pair.of(siv, caveatKey);

            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            } finally {
                encKey.destroy();
                finKey.destroy();
                Utils.wipe(tag);
                encryptedBlocks.clear();
            }
        }
    }

    private class Decryptor extends MessageProcessor<Decryptor> implements MessageDecryptor {
        private final Cipher cipher;
        private final byte[] siv;

        Decryptor(DestroyableSecretKey macKey, DestroyableSecretKey encKey, DestroyableSecretKey finKey,
                byte[] siv) {
            super(macKey, encKey, finKey);
            this.siv = siv.clone();
            this.cipher = getCipher(Cipher.DECRYPT_MODE, siv);
        }

        @Override
        Decryptor self() {
            return this;
        }

        @Override
        public MessageDecryptor decryptAndAuthenticate(byte[] data) {
            try {
                int numBytes = cipher.update(data, 0, data.length, data);
                assert numBytes == data.length;
                authenticate(data);
            } catch (ShortBufferException e) {
                throw new IllegalStateException(e);
            }

            return this;
        }

        @Override
        public Optional<DestroyableSecretKey> verify() {
            try {
                var leftOver = cipher.doFinal();
                assert leftOver.length == 0;

                var computedSiv = Arrays.copyOf(hmac(finKey, this.tag), 16);
                logger.trace("SIV: computed={}, provided={}", computedSiv, siv);
                var caveatKey = importKey(this.tag);
                logger.trace("Caveat Key: {}", caveatKey);
                if (MessageDigest.isEqual(computedSiv, siv)) {
                    return Optional.of(caveatKey);
                }

                return Optional.empty();
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                return Optional.empty();
            } finally {
                destroy();
            }
        }
    }
}
