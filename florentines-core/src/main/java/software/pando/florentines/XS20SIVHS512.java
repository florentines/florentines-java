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

import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;

import software.pando.crypto.nacl.ByteSlice;
import software.pando.crypto.nacl.Bytes;
import software.pando.crypto.nacl.Crypto;
import software.pando.crypto.nacl.Subtle;

/**
 * A {@link DEM} implementation based on a combination of the XSalsa20 stream cipher and HMAC-SHA-512-256 in a
 * Synthetic IV (SIV) mode of operation. HMAC is used to compute an authentication tag over an arbitrary number of
 * associated data blocks and the plaintext. This tag is then truncated to 16 bytes and used as the nonce for XSalsa20.
 */
final class XS20SIVHS512 implements DEM {
    private static final byte[] NUL = new byte[1];
    @Override
    public String getIdentifier() {
        return "XS20SIV-HS512";
    }

    @Override
    public SecretKey key(byte[] keyMaterial) {
        return Crypto.authKey(keyMaterial);
    }

    @Override
    public CipherState authenticate(SecretKey key, byte[]... data) {
        byte[] tag = cascadeMac(key, data);

        return new CipherState(Crypto.authKey(tag)) {
            @Override
            byte[] andEncrypt(byte[]... payloads) {
                var subKeys = deriveKeys(key);
                var finKey = subKeys[0]; var encKey = subKeys[1];
                byte[] siv = deriveSiv(finKey, tag);
                try (var cipher = Subtle.streamXSalsa20(encKey, Arrays.copyOf(siv, 24))) {
                    for (byte[] payload : payloads) {
                        cipher.process(ByteSlice.of(payload));
                    }
                }
                return siv;
            }
        };
    }

    @Override
    public Verifier decrypt(SecretKey key, byte[] siv, byte[]... ciphertexts) {
        // NB: don't actually perform decryption until verify method called
        return blocks -> {
            var subKeys = deriveKeys(key);
            var finKey = subKeys[0]; var encKey = subKeys[1];
            try (var cipher = Subtle.streamXSalsa20(encKey, Arrays.copyOf(siv, 24))) {
                for (byte[] ciphertext : ciphertexts) {
                    cipher.process(ByteSlice.of(ciphertext));
                }
            }

            byte[] tag = cascadeMac(key, blocks);
            byte[] computedSiv = deriveSiv(finKey, tag);
            if (!Bytes.equal(computedSiv, siv)) {
                for (byte[] payload : ciphertexts) {
                    Arrays.fill(payload, (byte) 0);
                    return Optional.empty();
                }
            }
            return Optional.of(Crypto.authKey(tag));
        };
    }

    private static byte[] cascadeMac(SecretKey macKey, byte[][] data) {
        byte[] tag = new byte[32];
        for (byte[] block : data) {
            // We append each data block with a NUL (0) byte to ensure domain separation with the use of HKDF to
            // derive the finalisation and encryption keys. The last byte of input to HKDF-Expand is always a byte in
            // the range 1..255, so this ensures the input never collides.
            tag = Crypto.auth(macKey, Utils.concat(block, NUL));
            macKey = Crypto.authKey(tag);
        }
        return tag;
    }

    private static byte[] deriveSiv(SecretKey finKey, byte[] tag) {
        try {
            return Arrays.copyOf(Crypto.auth(finKey, tag), 16);
        } finally {
            Utils.destroy(finKey);
        }
    }

    private static SecretKey[] deriveKeys(SecretKey key) {
        byte[] keyMaterial = Crypto.kdfDeriveFromKey(key, "Florentine-XS20SIV-HS512-SubKeys".getBytes(UTF_8), 64);
        SecretKey finKey = Crypto.authKey(ByteSlice.ofRange(keyMaterial, 0, 32));
        SecretKey encKey = Subtle.streamXSalsa20Key(ByteSlice.ofRange(keyMaterial, 32, 64));
        Arrays.fill(keyMaterial, (byte) 0);
        return new SecretKey[] { finKey, encKey };
    }
}
