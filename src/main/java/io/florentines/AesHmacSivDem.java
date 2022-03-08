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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

/**
 * A DEM implementation using a combination of AES in CTR mode with HMAC-SHA-256 in a
 * <a href="https://datatracker.ietf.org/doc/html/rfc5297">Synthetic IV</a>
 * construction. Rather than using the s2v construction with AES-CMAC, this DEM uses HMAC in a cascade construction
 * to process multiple blocks of input and then finalizes the tag using a separate key to prevent length extension
 * attacks, following the design of NMAC. The final 256-bit tag is split into two components: the first 16 bytes are
 * used as the SIV and should be stored alongside the ciphertext to ensure decryption is possible, while the last 16
 * bytes become a tag for appending caveats as in Macaroons. This latter tag will be replaced every time a caveat is
 * appended. As a strong PRF, the two segments of the tag can be considered as independent pseudorandom values and it
 * is not possible to reconstruct the original caveat tag from the SIV or vice versa.
 */
final class AesHmacSivDem implements DEM {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
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
    public DestroyableSecretKey generateFreshKey() {
        var bytes = SECURE_RANDOM.generateSeed(32);
        return new DestroyableSecretKey(MAC_ALGORITHM, bytes);
    }

    @Override
    public DestroyableSecretKey importKey(byte[] keyMaterial) {
        return new DestroyableSecretKey(MAC_ALGORITHM, keyMaterial);
    }

    @Override
    public MessageEncryptor beginEncryption(SecretKey demKey) {
        var expandedKey = HKDF.expand(demKey, getIdentifier().getBytes(UTF_8), 3*32);
        var macKey = new DestroyableSecretKey(MAC_ALGORITHM, "RAW", expandedKey, 0, 32);
        var encKey = new DestroyableSecretKey("AES", "RAW", expandedKey, 32, 32);
        var finKey = new DestroyableSecretKey(MAC_ALGORITHM, "RAW", expandedKey, 64, 32);
        Arrays.fill(expandedKey, (byte) 0);

        return new Encryptor(macKey, encKey, finKey);
    }

    @Override
    public MessageDecryptor beginDecryption(SecretKey demKey, byte[] siv) {
        var expandedKey = HKDF.expand(demKey, getIdentifier().getBytes(UTF_8), 3*32);
        var macKey = new DestroyableSecretKey(MAC_ALGORITHM, "RAW", expandedKey, 0, 32);
        var encKey = new DestroyableSecretKey("AES", "RAW", expandedKey, 32, 32);
        var finKey = new DestroyableSecretKey(MAC_ALGORITHM, "RAW", expandedKey, 64, 32);
        Arrays.fill(expandedKey, (byte) 0);

        return new Decryptor(macKey, encKey, finKey, siv);
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

        public T authenticate(byte[]... data) {
            for (var packet : data) {
                var macKey = new DestroyableSecretKey(MAC_ALGORITHM, this.tag);
                this.tag = Crypto.hmac(macKey, packet);
                macKey.destroy();
            }
            return self();
        }

        void preventExtension() {
            this.tag = Crypto.hmac(finKey, this.tag);
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
            Arrays.fill(tag, (byte) 0);
        }
    }

    private static class Encryptor extends MessageProcessor<Encryptor> implements MessageEncryptor {
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
            var siv = Arrays.copyOf(Crypto.hmac(finKey, this.tag), 16);
            var caveatKey = new DestroyableSecretKey(MAC_ALGORITHM, this.tag);
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
                Arrays.fill(tag, (byte) 0);
                encryptedBlocks.clear();
            }
        }
    }

    private static class Decryptor extends MessageProcessor<Decryptor> implements MessageDecryptor {
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

                var computedSiv = Arrays.copyOf(Crypto.hmac(finKey, this.tag), 16);
                var caveatKey = new DestroyableSecretKey(MAC_ALGORITHM, this.tag);
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
