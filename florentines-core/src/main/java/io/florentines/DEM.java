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
import java.util.List;

import static io.florentines.CryptoUtils.secureRandomBytes;
import static java.nio.charset.StandardCharsets.*;

/**
 * A Data Encapsulation Mechanism (DEM). The Florentines DEM is a simple combination of AES in CTR mode and
 * HMAC-SHA-256 in an Encrypt-then-MAC generic combination. Note that, as is traditional with DEMs, it is assumed that
 * each key is used to encrypt exactly one message, and therefore no IV or nonce is used. This class is therefore not
 * suitable for general-purpose usage.
 */
final class DEM {

    static final String IDENTIFIER = "A128CTR-HS256";
    static final DEM INSTANCE = new DEM();

    private static final String MAC_ALG = "HmacSHA256";
    private static final String MAC_KEY_ALG = MAC_ALG;
    private static final String ENC_ALG = "AES/CTR/NoPadding";
    private static final String ENC_KEY_ALG = "AES";
    private static final IvParameterSpec FIXED_IV = new IvParameterSpec((IDENTIFIER + "-IV").getBytes(UTF_8));

    private static final int MAC_KEY_OFFSET = 0;
    private static final int MAC_KEY_LENGTH = 16;
    private static final int ENC_KEY_OFFSET = MAC_KEY_LENGTH;
    private static final int ENC_KEY_LENGTH = 16;

    private DEM() {}

    String identifier() {
        return IDENTIFIER;
    }

    DestroyableSecretKey freshKey() {
        return new DestroyableSecretKey(identifier(), secureRandomBytes(32));
    }

    DestroyableSecretKey encapsulate(DestroyableSecretKey key, byte[] content, byte[] assocData) {
        return withSubKeys(key, (macKey, encKey) -> {
            aesCtr(encKey, content);
            var tag = SHA256.hmacCascade(macKey, List.of(assocData, content));
            return new DestroyableSecretKey(identifier(), tag);
        });
    }

    DestroyableSecretKey decapsulate(DestroyableSecretKey key, byte[] content, byte[] assocData) {
        return withSubKeys(key, (macKey, encKey) -> {
            var tag = SHA256.hmacCascade(macKey, List.of(assocData, content));
            aesCtr(encKey, content);
            return new DestroyableSecretKey(identifier(), tag);
        });
    }

    private <T> T withSubKeys(DestroyableSecretKey key, SubKeyAction<T> action) {
        if (key == null || !IDENTIFIER.equals(key.getAlgorithm()) || key.rawKeyMaterial().length != 32) {
            throw new IllegalArgumentException("invalid DEM key");
        }
        try (var macKey = new DestroyableSecretKey(MAC_KEY_ALG, key.rawKeyMaterial(), MAC_KEY_OFFSET, MAC_KEY_LENGTH);
             var encKey = new DestroyableSecretKey(ENC_KEY_ALG, key.rawKeyMaterial(), ENC_KEY_OFFSET, ENC_KEY_LENGTH))
        {
            try {
                return action.apply(macKey, encKey);
            } catch (GeneralSecurityException e) {
                throw new AssertionError(e);
            }
        }
    }

    private void aesCtr(DestroyableSecretKey aesKey, byte[] message) throws GeneralSecurityException {
        var cipher = Cipher.getInstance(ENC_ALG);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, FIXED_IV);
        int bytesWritten = cipher.update(message, 0, message.length, message);
        assert bytesWritten == message.length;
    }

    private interface SubKeyAction<T> {
        T apply(DestroyableSecretKey macKey, DestroyableSecretKey encKey) throws GeneralSecurityException;
    }
}
