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
import static java.util.Objects.requireNonNull;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
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
    public DEM.Processor begin(DestroyableSecretKey key, byte[] siv) {
        var expandedKey = HKDF.expand(key, getIdentifier().getBytes(UTF_8), 3*32);
        var macKey = new DestroyableSecretKey(MAC_ALGORITHM, "RAW", expandedKey, 0, 32);
        var encKey = new DestroyableSecretKey("AES", "RAW", expandedKey, 32, 32);
        var finKey = new DestroyableSecretKey(MAC_ALGORITHM, "RAW", expandedKey, 64, 32);
        Arrays.fill(expandedKey, (byte) 0);

        return new Processor(macKey, encKey, finKey, siv);
    }

    private static class Processor implements DEM.Processor {

        private DestroyableSecretKey macKey;
        private final DestroyableSecretKey encKey;
        private final DestroyableSecretKey finKey;
        private final byte[] siv;

        private byte[] tag = new byte[32];

        private Processor(DestroyableSecretKey macKey, DestroyableSecretKey encKey, DestroyableSecretKey finKey,
                byte[] siv) {
            this.macKey = requireNonNull(macKey);
            this.encKey = requireNonNull(encKey);
            this.finKey = requireNonNull(finKey);
            this.siv = requireNonNull(siv);
            if (siv.length != 16) {
                throw new IllegalArgumentException("SIV must be 16 bytes");
            }
        }

        @Override
        public DEM.Processor authenticate(byte[]... data) {

            for (var packet : data) {
                tag = Crypto.hmac(macKey, packet);
                macKey.destroy();
                macKey = new DestroyableSecretKey(MAC_ALGORITHM, tag);
            }

            return this;
        }

        @Override
        public byte[] encrypt(byte[]... data) {
            authenticate(data);
            tag = finalizeTag(finKey, tag);
            System.arraycopy(tag, 0, this.siv, 0, this.siv.length);
            var siv = syntheticIv(tag);

            try {
                var cipher = CIPHER_THREAD_LOCAL.get();
                cipher.init(Cipher.ENCRYPT_MODE, encKey, siv);
                for (var packet : data) {
                    int numBytes = cipher.update(packet, 0, packet.length, packet);
                    assert numBytes == packet.length;
                }
            } catch (GeneralSecurityException e) {
                CIPHER_THREAD_LOCAL.remove();
                throw new AssertionError(e);
            } finally {
                macKey.destroy();
                encKey.destroy();
                finKey.destroy();;
            }

            assert tag.length == 32;
            return Arrays.copyOfRange(tag, 16, 32);
        }

        @Override
        public Optional<byte[]> decrypt(byte[]... data) {
            try {
                var siv = syntheticIv(this.siv);
                var cipher = CIPHER_THREAD_LOCAL.get();
                cipher.init(Cipher.DECRYPT_MODE, encKey, siv);

                for (var packet : data) {
                    int numBytes = cipher.update(packet, 0, packet.length, packet);
                    assert numBytes == packet.length;
                }

                authenticate(data);
                tag = finalizeTag(finKey, tag);
                if (!MessageDigest.isEqual(this.siv, Arrays.copyOf(this.tag, 16))) {
                    for (var packet : data) {
                        Arrays.fill(packet, (byte) 0);
                        Arrays.fill(this.tag, (byte) 0);
                    }
                    return Optional.empty();
                }

                return Optional.of(Arrays.copyOfRange(tag, 16, 32));
            } catch (GeneralSecurityException e) {
                return Optional.empty();
            } finally {
                macKey.destroy();
                encKey.destroy();
                finKey.destroy();
            }
        }
    }

    private static byte[] finalizeTag(DestroyableSecretKey finKey, byte[] tag) {
        return Crypto.hmac(finKey, tag);
    }

    private static IvParameterSpec syntheticIv(byte[] tag) {
        var siv = Arrays.copyOf(tag, 16);
        siv[12] &= 0x7F;
        siv[8] &= 0x7F;
        return new IvParameterSpec(siv);
    }
}
