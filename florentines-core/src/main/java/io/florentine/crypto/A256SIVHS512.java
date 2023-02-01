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
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

final class A256SIVHS512 implements DEM {
    private static final byte[] KDF_CONTEXT = "Florentine-DEM-A256SIV-HS512-SubKeyDerivation".getBytes(UTF_8);

    @Override
    public String getAlgorithmIdentifier() {
        return "A256SIV-HS512";
    }

    @Override
    public SecretKey generateKey() {
        return Crypto.authKeyGen();
    }

    @Override
    public SecretKey importKey(byte[] keyMaterial, int offset, int length) {
        return Crypto.authKey(ByteSlice.of(keyMaterial, offset, length));
    }

    @Override
    public int getTagSizeInBytes() {
        return 32;
    }

    @Override
    public byte[] encrypt(SecretKey key, Iterable<byte[]> messages, Iterable<byte[]> context) {
        var keyMaterial = Crypto.kdfDeriveFromKey(key, KDF_CONTEXT, 32*3);
        var macKey = Crypto.authKey(ByteSlice.of(keyMaterial, 0, 32));
        var encKey = new SecretKeySpec(keyMaterial, 32, 32, "AES");
        var finKey = Crypto.authKey(ByteSlice.of(keyMaterial, 64, 32));

        byte[] tag = new byte[32];
        for (var block : context) {
            tag = Crypto.auth(macKey, block);
            Utils.destroy(macKey);
            macKey = Crypto.authKey(tag);
        }

        for (var block : messages) {
            tag = Crypto.auth(macKey, block);
            Utils.destroy(macKey);
            macKey = Crypto.authKey(tag);
        }

        ctr(encKey, tag, messages);
        Utils.destroy(macKey, finKey, encKey);

        return tag;
    }

    @Override
    public Optional<Iterable<byte[]>> decrypt(SecretKey key, Iterable<byte[]> messages, Iterable<byte[]> context,
                                        byte[] siv) {
        var keyMaterial = Crypto.kdfDeriveFromKey(key, KDF_CONTEXT, 3*32);
        var macKey = Crypto.authKey(ByteSlice.of(keyMaterial, 0, 32));
        var encKey = new SecretKeySpec(keyMaterial, 32, 32, "AES");
        var finKey = Crypto.authKey(ByteSlice.of(keyMaterial, 64, 32));

        ctr(encKey, siv, messages);

        byte[] tag = new byte[32];
        for (var block : context) {
            tag = Crypto.auth(macKey, block);
            Utils.destroy(macKey);
            macKey = Crypto.authKey(tag);
        }
        for (var block : messages) {
            tag = Crypto.auth(macKey, block);
            Utils.destroy(macKey);
            macKey = Crypto.authKey(tag);
        }

        if (!MessageDigest.isEqual(siv, tag)) {
            ctr(encKey, siv, messages);
            return Optional.empty();
        }

        return Optional.of(messages);
    }

    private void ctr(SecretKey encKey, byte[] siv, Iterable<byte[]> messages) {
        try {
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(siv, 0, 16));

            for (byte[] message : messages) {
                int numBytes = cipher.update(message, 0, message.length, message);
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
}
