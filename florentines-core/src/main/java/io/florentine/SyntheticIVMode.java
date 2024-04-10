/*
 * Copyright 2024 Neil Madden.
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

package io.florentine;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.crypto.SecretKey;

final class SyntheticIVMode implements KeyWrapCipher {
    public static final byte[] PRF_KEY_LABEL = "Florentine-SIV-SubKeys".getBytes(UTF_8);
    private final String algorithm;
    private final StreamCipher cipher;
    private final PRF prf;

    SyntheticIVMode(String algorithm, StreamCipher streamCipher, PRF prf) {
        this.algorithm = algorithm;
        this.cipher = streamCipher;
        this.prf = prf;
    }

    @Override
    public String algorithm() {
        return algorithm;
    }

    @Override
    public byte[] wrap(SecretKey wrapKey, SecretKey keyToWrap, byte[] context) {
        var keyMaterial = HKDF.expand(wrapKey, PRF_KEY_LABEL, 64);
        try (var prfKey = new DestroyableSecretKey(keyMaterial, 0, 32, prf.algorithm());
             var encKey = new DestroyableSecretKey(keyMaterial, 32, 64, cipher.algorithm())) {

            var encodedKey = keyToWrap.getEncoded();
            var siv = Arrays.copyOf(prf.applyMulti(prfKey, List.of(context, encodedKey)), 16);
            cipher.cipher(encKey, siv, encodedKey);

            return CryptoUtils.concat(siv, encodedKey);
        }
    }

    @Override
    public Optional<DestroyableSecretKey> unwrap(SecretKey unwrapKey, byte[] wrappedKey, String wrappedKeyAlgorithm,
                                                 byte[] context) {
        var keyMaterial = HKDF.expand(unwrapKey, PRF_KEY_LABEL, 64);
        try (var prfKey = new DestroyableSecretKey(keyMaterial, 0, 32, prf.algorithm());
             var encKey = new DestroyableSecretKey(keyMaterial, 32, 64, cipher.algorithm())) {

            var providedSiv = Arrays.copyOf(wrappedKey, 16);
            var unwrappedKey = Arrays.copyOfRange(wrappedKey, 16, wrappedKey.length);

            cipher.cipher(encKey, providedSiv, unwrappedKey);
            var computedSiv = Arrays.copyOf(prf.applyMulti(prfKey, List.of(context, unwrappedKey)), 16);

            if (!MessageDigest.isEqual(computedSiv, providedSiv)) {
                CryptoUtils.wipe(unwrappedKey);
                return Optional.empty();
            }
            return Optional.of(new DestroyableSecretKey(unwrappedKey, wrappedKeyAlgorithm));
        }
    }
}
