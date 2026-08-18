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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;

import static io.florentines.CryptoUtils.secureRandomBytes;

/**
 * A Data Encapsulation Mechanism.
 */
public interface DEM {
    String identifier();
    DestroyableSecretKey freshKey();

    DestroyableSecretKey encapsulate(DestroyableSecretKey key, byte[] plaintext,  byte[] assocData);
    DestroyableSecretKey decapsulate(DestroyableSecretKey key, byte[] ciphertext, byte[] assocData);

    final class A128SIV_HS256 implements DEM {
        private static final String MAC_ALG = "HmacSHA256";
        private static final String ENC_ALG = "AES/CTR/NoPadding";

        @Override
        public String identifier() {
            return "A128SIV-HS256";
        }

        @Override
        public DestroyableSecretKey freshKey() {
            return new DestroyableSecretKey(identifier(), secureRandomBytes(32));
        }

        @Override
        public DestroyableSecretKey encapsulate(DestroyableSecretKey key, byte[] plaintext, byte[] assocData) {
            try (var macKey = new DestroyableSecretKey(MAC_ALG, key.rawKeyMaterial(), 0, 16);
                 var encKey = new DestroyableSecretKey(ENC_ALG.split("/")[0], key.rawKeyMaterial(), 16, 16)) {

                var tag = SHA256.hmacCascade(macKey, assocData, plaintext);
                var siv = new IvParameterSpec(tag, 0, 16);
                var cipher = Cipher.getInstance(ENC_ALG);
                cipher.init(Cipher.ENCRYPT_MODE, encKey, siv);
                cipher.update(plaintext, 0, plaintext.length, plaintext);
                cipher.update(tag, 0, 32, tag);
                cipher.doFinal();


            } catch (GeneralSecurityException e) {
                throw new AssertionError(e);
            }
            return null;
        }

        @Override
        public DestroyableSecretKey decapsulate(DestroyableSecretKey key, byte[] ciphertext, byte[] assocData) {
            return null;
        }
    }
}
