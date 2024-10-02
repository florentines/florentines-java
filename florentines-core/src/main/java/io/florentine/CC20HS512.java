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

import java.util.Optional;

import software.pando.crypto.nacl.Bytes;

final class CC20HS512 extends DEM {
    private static final byte[] ZERO_NONCE = new byte[12];
    private static final byte[] NEXT_NONCE = new byte[12];
    static {
        NEXT_NONCE[0] = 1;
    }

    private final StreamCipher cipher = StreamCipher.CHACHA20;
    private final PRF prf = PRF.HS512;

    @Override
    public String identifier() {
        return "CC20-HS512";
    }

    @Override
    DestroyableSecretKey generateKey() {
        var bytes = Bytes.secureRandom(32);
        try {
            return new DestroyableSecretKey(bytes, identifier());
        } finally {
            Utils.wipe(bytes);
        }
    }

    @Override
    byte[] encapsulate(DestroyableSecretKey demKey, Iterable<? extends Record> records) {
        Require.notEmpty(records, "Must provide at least one record");
        var key = validateKey(demKey);
        for (var record : records) {
            var macKey = cipher.process(key, ZERO_NONCE, new byte[32]);
            cipher.process(key, NEXT_NONCE, record.secretContent());
            key = prf.cascade(macKey, record.assocData(), record.publicContent(), record.secretContent());
        }
        return key;
    }

    @Override
    Optional<byte[]> decapsulate(DestroyableSecretKey demKey, Iterable<? extends Record> records, byte[] tag) {
        Require.notEmpty(records, "Must provide at least one record");
        boolean valid = false;
        var key = validateKey(demKey);
        try {
            for (var record : records) {
                var content = record.secretContent();
                var macKey = cipher.process(key, ZERO_NONCE, new byte[32]);
                key = prf.cascade(macKey, record.assocData(), record.publicContent(), content);
                cipher.process(key, NEXT_NONCE, content);
            }
            valid = Bytes.equal(key, tag);
        } finally {
            if (!valid) {
                // Avoid releasing unverified plaintext
                records.forEach(record -> Utils.wipe(record.secretContent()));
            }
        }

        return valid ? Optional.of(key) : Optional.empty();
    }

    @Override
    KeyWrapper asKeyWrapper() {
        return new SIV(cipher, prf);
    }

    private byte[] validateKey(DestroyableSecretKey key) {
        if (!identifier().equals(key.getAlgorithm())) {
            throw new IllegalArgumentException("invalid algorithm");
        }
        var bytes = key.getKeyBytes();
        if (bytes.length != 32) {
            throw new IllegalArgumentException("invalid key");
        }
        return bytes;
    }
}
