/*
 * Copyright 2023 Neil Madden.
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

package io.florentine.crypto;

import io.florentine.Utils;
import software.pando.crypto.nacl.ByteSlice;
import software.pando.crypto.nacl.Crypto;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

final class A256SIVHS512 implements DEM {
    private static final byte[] KDF_CONTEXT = "Florentine-DEM-A256SIV-HS512-SubKeyDerivation".getBytes(UTF_8);
    private static final int SIV_SIZE = 16;

    @Override
    public String getAlgorithmIdentifier() {
        return "A256SIV-HS512";
    }

    @Override
    public SecretKey generateKey() {
        return new DerivedKeys(Crypto.authKeyGen());
    }

    @Override
    public SecretKey importKey(byte[] keyMaterial, int offset, int length) {
        return new DerivedKeys(Crypto.authKey(ByteSlice.of(keyMaterial, offset, length)));
    }

    @Override
    public int tagSizeBytes() {
        return SIV_SIZE;
    }

    @Override
    public byte[] hash(byte[] data) {
        return Arrays.copyOf(Crypto.hash(data), 32);
    }

    @Override
    public DataEncapsulator beginEncapsulation(SecretKey key) {
        System.out.println("----");
        var keys = DerivedKeys.from(key).orElseThrow(() -> new IllegalArgumentException("Invalid key"));
        return new DataEncapsulator() {

            private SecretKey macKey = keys.macKey;
            private final List<byte[]> toEncrypt = new ArrayList<>();

            @Override
            public DataEncapsulator withContext(byte[]... context) {
                System.out.println("Context: ");
                Arrays.stream(context).map(Utils::hexDump).forEach(System.out::println);
                macKey = authMulti(macKey, context);
                return this;
            }

            @Override
            public DataEncapsulator encapsulate(byte[] message) {
                System.out.println("Encrypt:\n" + Utils.hexDump(message));
                macKey = authMulti(macKey, message);
                System.out.println("To Encrypt: " + message);
                toEncrypt.add(message);
                return this;
            }

            @Override
            public KeyAndTag done() {
                System.out.println("----");
                var siv = Arrays.copyOf(Crypto.auth(keys.finKey, macKey.getEncoded()), SIV_SIZE);
                ctr(keys.encKey, siv, toEncrypt);
                toEncrypt.clear();
                return new KeyAndTag(macKey, siv);
            }
        };
    }

    @Override
    public DataDecapsulator beginDecapsulation(SecretKey key, byte[] siv) {
        System.out.println("----");
        var keys = DerivedKeys.from(key).orElseThrow(() -> new IllegalArgumentException("Invalid key"));
        return new DataDecapsulator() {
            private SecretKey macKey = keys.macKey;
            private final List<byte[]> plaintexts = new ArrayList<>();

            @Override
            public DataDecapsulator withContext(byte[]... context) {
                System.out.println("Context: ");
                Arrays.stream(context).map(Utils::hexDump).forEach(System.out::println);

                macKey = authMulti(macKey, context);
                return this;
            }

            @Override
            public DataDecapsulator decapsulate(byte[] message) {

                ctr(keys.encKey, siv, List.of(message));
                plaintexts.add(message);
                System.out.println("Decrypt:\n" + Utils.hexDump(message));

                macKey = authMulti(macKey, message);
                return this;
            }

            @Override
            public Optional<SecretKey> verify() {
                System.out.println("----");
                var computedSiv = Arrays.copyOf(Crypto.auth(keys.finKey, macKey.getEncoded()), SIV_SIZE);
                Utils.destroy(keys);
                if (!MessageDigest.isEqual(computedSiv, siv)) {
                    // Wipe any released plaintext just in case
                    plaintexts.forEach(plaintext -> Arrays.fill(plaintext, (byte) 0));
                    return Optional.empty();
                }
                plaintexts.clear();
                return Optional.of(macKey);
            }
        };
    }

    private static SecretKey authMulti(SecretKey macKey, byte[]... chunks) {
        Utils.rejectIf(macKey.isDestroyed(), "Key has been destroyed");
        for (var block : chunks) {
            macKey = Crypto.authKey(Crypto.auth(macKey, block));
        }
        return macKey;
    }

    private static void ctr(SecretKey encKey, byte[] siv, Iterable<byte[]> messages) {
        System.out.println("Key:\n" + Utils.hexDump(encKey.getEncoded()));
        System.out.println("SIV:\n" + Utils.hexDump(siv));
        Utils.rejectIf(encKey.isDestroyed(), "Key has been destroyed");
        try {
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(siv));

            for (byte[] message : messages) {
                System.out.println("Encrypting: " + message);
                System.out.println("In:\n" + Utils.hexDump(message));
                int numBytes = cipher.update(message, 0, message.length, message);
                System.out.println("Out:\n" + Utils.hexDump(message));

                if (numBytes != message.length) {
                    throw new IllegalStateException("Cipher failed to encrypt message");
                }
            }

            var result = cipher.doFinal();
            if (result != null && result.length > 0) {
                throw new IllegalStateException("Cipher returned unexpected extra data");
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new AssertionError("AES-CTR not implemented by JVM", e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static class DerivedKeys implements SecretKey {
        private final byte[] originalKeyMaterial;

        final SecretKey macKey;
        final SecretKey finKey;
        final SecretKey encKey;

        DerivedKeys(SecretKey key) {
            this.originalKeyMaterial = key.getEncoded();
            var keyMaterial = Crypto.kdfDeriveFromKey(key, KDF_CONTEXT, 3*32);
            this.macKey = Crypto.authKey(ByteSlice.of(keyMaterial, 0, 32));
            this.encKey = new SecretKeySpec(keyMaterial, 32, 32, "AES");
            this.finKey = Crypto.authKey(ByteSlice.of(keyMaterial, 64, 32));
            Arrays.fill(keyMaterial, (byte) 0);
        }

        @Override
        public String getAlgorithm() {
            return "A256SIV-HS512";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return originalKeyMaterial.clone();
        }

        @Override
        public void destroy() {
//            Arrays.fill(originalKeyMaterial, (byte) 0);
//            Utils.destroy(macKey, finKey, encKey);
        }

        @Override
        public boolean isDestroyed() {
            return macKey.isDestroyed();
        }

        static Optional<DerivedKeys> from(SecretKey key) {
            return Optional.of(new DerivedKeys(key));
        }
    }
}
