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

import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;

import software.pando.crypto.nacl.Bytes;

final class SIV implements KeyWrapper {
    private final StreamCipher cipher;
    private final PRF prf;
    private final byte[] zeroNonce;

    SIV(StreamCipher cipher, PRF prf) {
        this.cipher = cipher;
        this.prf = prf;
        this.zeroNonce = new byte[cipher.nonceSizeBytes()];
    }

    @Override
    public byte[] wrap(SecretKey wrapKey, SecretKey keyToWrap) {
        var macKey = cipher.process(wrapKey.getEncoded(), zeroNonce, new byte[32]);
        var keyBytes = keyToWrap.getEncoded();
        var siv = Arrays.copyOf(
                prf.cascade(macKey, keyToWrap.getAlgorithm().getBytes(UTF_8), keyBytes),
                cipher.nonceSizeBytes());
        return Utils.concat(siv, cipher.process(wrapKey.getEncoded(), siv, keyBytes));
    }

    @Override
    public Optional<DestroyableSecretKey> unwrap(SecretKey unwrapKey, byte[] wrappedKey, String keyAlgorithm) {
        var macKey = cipher.process(unwrapKey.getEncoded(), zeroNonce, new byte[32]);
        var providedSiv = Arrays.copyOf(wrappedKey, cipher.nonceSizeBytes());
        wrappedKey = Arrays.copyOfRange(wrappedKey, cipher.nonceSizeBytes(), wrappedKey.length);
        cipher.process(unwrapKey.getEncoded(), providedSiv, wrappedKey);
        try {
            var computedSiv = Arrays.copyOf(
                    prf.cascade(macKey, keyAlgorithm.getBytes(UTF_8), wrappedKey),
                    cipher.nonceSizeBytes());

            if (!Bytes.equal(computedSiv, providedSiv)) {
                return Optional.empty();
            }
            return Optional.of(new DestroyableSecretKey(wrappedKey, keyAlgorithm));
        } finally {
            Arrays.fill(wrappedKey, (byte) 0);
        }
    }
}
