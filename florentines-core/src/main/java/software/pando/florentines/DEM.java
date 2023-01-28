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

package software.pando.florentines;

import software.pando.crypto.nacl.ByteSlice;
import software.pando.crypto.nacl.Crypto;
import software.pando.crypto.nacl.Subtle;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Optional;

/**
 * A Data Encapsulation Mechanism (DEM). DEMs provide authenticated encryption with associated data (AEAD), but on the
 * relaxed assumption that the encryption key is only used for a single message. All DEMs <strong>MUST</strong> be
 * <em>compactly committing</em>. DEMs <em>SHOULD</em> also provide Deterministic Authenticated Encryption (DAE) in the
 * sense of Rogaway and Shrimpton, in case a protocol error or implementation mistake causes a key to be reused.
 */
interface DEM {

    String getAlgorithmIdentifier();
    SecretKey generateKey();
    SecretKey importKey(byte[] keyMaterial, int offset, int length);
    default SecretKey importKey(byte[] keyMaterial) {
        return importKey(keyMaterial, 0, keyMaterial.length);
    }

    byte[] encrypt(SecretKey key, byte[] plaintext, byte[]... associatedData);
    Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext, byte[] tag, byte[]... associatedData);


    /**
     * The initial DEM defined for Florentines is based on the XSalsa20 stream cipher used in a Synthetic IV (SIV)
     * construction using HMAC-SHA-512 truncated to 256 bits as the MAC.
     */
    DEM XS20SIVHS512 = new DEM() {
        private final byte[] ZERO_NONCE = new byte[24];

        @Override
        public String getAlgorithmIdentifier() {
            return "XS20SIV-HS512";
        }

        @Override
        public SecretKey generateKey() {
            return Subtle.streamXSalsa20KeyGen();
        }

        @Override
        public SecretKey importKey(byte[] keyMaterial, int offset, int length) {
            return Subtle.streamXSalsa20Key(ByteSlice.of(keyMaterial, offset, length));
        }

        @Override
        public byte[] encrypt(SecretKey key, byte[] plaintext, byte[]... associatedData) {
            var macKey = macKey(key);
            var tag = Crypto.authMulti(macKey, Utils.concat(plaintext, associatedData));
            // TODO: adjust Salty Coffee API to avoid this temporary copy. Either allow nonces > 24 bytes or allow offset/length
            var siv = Arrays.copyOf(tag, 24);
            try (var cipher = Subtle.streamXSalsa20(key, siv)) {
                cipher.process(ByteSlice.of(plaintext));
            }
            return tag;
        }

        @Override
        public Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext, byte[] tag, byte[]... associatedData) {
            var macKey = macKey(key);
            try (var cipher = Subtle.streamXSalsa20(key, Arrays.copyOf(tag, 24))) {
                cipher.process(ByteSlice.of(ciphertext));
            }

            if (!Crypto.authVerifyMulti(macKey, Utils.concat(ciphertext, associatedData), tag)) {
                Arrays.fill(ciphertext, (byte) 0);
                return Optional.empty();
            }
            return Optional.of(ciphertext);
        }

        private SecretKey macKey(SecretKey key) {
            try (var cipher = Subtle.streamXSalsa20(key, ZERO_NONCE)) {
                var macKeyBytes = new byte[32];
                cipher.process(ByteSlice.of(macKeyBytes));
                return Crypto.authKey(macKeyBytes);
            }
        }
    };
}
