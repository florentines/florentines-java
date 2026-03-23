/*
 * Copyright 2025-2026 Neil Madden.
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

package io.florentine.dem;

import io.florentine.Bytes;
import io.florentine.DataEncapsulationKey;
import io.florentine.crypto.CryptoUtils;
import io.florentine.crypto.HMAC;
import io.florentine.crypto.HMAC.HmacKey;
import io.florentine.crypto.StreamCipher;
import io.florentine.crypto.StreamCipher.DataEncryptionKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;

/**
 * A generic {@link DEM} implementation based on a combination of a committing pseudorandom function (PRF)
 * and a length-preserving stream cipher in a Synthetic IV (SIV) construction. To encapsulate a message, first the PRF
 * is used to compute a tag over the plaintext(s) of the secret data and any associated public data. The first 16 bytes
 * of the second half of this tag are used as the Initialization Vector (IV, or nonce) to encrypt the secret data
 * (in place). The first half of the tag is then also encrypted, and this becomes the next DEM key (effectively
 * performing a symmetric ratchet for each call to encapsulate).
 */
abstract class SyntheticIVMode extends DEM {
    private static final Logger log = LoggerFactory.getLogger(SyntheticIVMode.class);
    private static final int SIV_LEN_BYTES = 16;

    private final HMAC prf;
    private final StreamCipher streamCipher;
    private final byte[] kdfSalt;
    private final int keyLen;

    SyntheticIVMode(String identifier, HMAC prf, StreamCipher streamCipher) {
        super(identifier);
        this.prf = prf;
        this.streamCipher = requireNonNull(streamCipher, "streamCipher");
        this.kdfSalt = ("Florentine-DEM-" + identifier + "-SubKeys").getBytes(US_ASCII);
        this.keyLen = prf.getKeyLengthBytes();
    }

    @Override
    public DataEncapsulationKey importKey(byte[] keyMaterial) {
        if (keyMaterial.length < prf.getKeyLengthBytes()) {
            throw new IllegalArgumentException("key material must be at least " + prf.getKeyLengthBytes() + " bytes");
        }
        return new DataEncapsulationKey(keyMaterial, 0, prf.getKeyLengthBytes(), identifier());
    }

    @Override
    public KeyAndTag encapsulate(DataEncapsulationKey key, List<byte[]> publicData, List<byte[]> secretData) {
        if (publicData.isEmpty() && secretData.isEmpty()) {
            throw new IllegalArgumentException("no data specified");
        }
        try (var keys = validateAndExpandKey(key)) {

            var tag = prf.cascade(keys.hmacKey, concat(publicData, secretData));
            assert tag.length >= SIV_LEN_BYTES*2;
            var mid = tag.length / 2;
            var siv = Arrays.copyOfRange(tag, mid, mid + SIV_LEN_BYTES);

            var cipher = streamCipher.begin(keys.encKey, siv);
            secretData.forEach(cipher::encipher);

            // Encrypt the tag to prevent length extension
            cipher.encipher(tag, 0, mid);
            return new KeyAndTag(new DataEncapsulationKey(tag, 0, mid, identifier()), siv);
        }
    }

    @Override
    public Optional<DataEncapsulationKey> decapsulate(DataEncapsulationKey key, List<byte[]> publicData, List<byte[]> secretData, byte[] siv) {
        if (publicData.isEmpty() && secretData.isEmpty()) {
            throw new IllegalArgumentException("no data specified");
        }
        if (siv.length != SIV_LEN_BYTES) {
            log.debug("Invalid SIV length {} - must be {} bytes", siv.length, SIV_LEN_BYTES);
            return Optional.empty();
        }

        try (var keys = validateAndExpandKey(key)) {

            var cipher = streamCipher.begin(keys.encKey, siv);
            secretData.forEach(cipher::decipher);

            var computedTag = prf.cascade(keys.hmacKey, concat(publicData, secretData));

            if (Bytes.constantTimeEquals(siv, Arrays.copyOfRange(computedTag, keyLen, keyLen + SIV_LEN_BYTES))) {
                cipher.encipher(computedTag, 0, keyLen);
                return Optional.of(new DataEncapsulationKey(computedTag, 0, keyLen, identifier()));
            } else {
                // Avoid releasing unverified plaintext
                CryptoUtils.wipe(secretData.toArray(byte[][]::new));
            }
        }
        return Optional.empty();
    }

    private Keys validateAndExpandKey(DataEncapsulationKey key) {
        if (key == null || !Objects.equals(identifier(), key.getAlgorithm())
                || !"RAW".equals(key.getFormat()) || key.isDestroyed() || key.getEncoded() == null
                || key.getEncoded().length != keyLen) {
            throw new IllegalArgumentException("invalid key");
        }
        // In this implementation we use the DEM key directly as the PRF key, and then use
        // (effectively) HKDF-Extract to derive an independent encryption key. This fundamentally
        // relies on the PRF being a Dual-PRF, so is really only safe with HMAC. TODO: fix this...
        var prfKey = prf.importKey(key.getEncoded(), 0);
        byte[] keyMaterial = null;
        try (var saltKey = prf.importKey(kdfSalt, 0)) {
            keyMaterial = prf.process(saltKey, key.getEncoded());
            return new Keys(prfKey, streamCipher.importKey(keyMaterial, 0));
        } finally {
            CryptoUtils.wipe(keyMaterial);
        }
    }

    private static Iterable<byte[]> concat(List<byte[]> a, List<byte[]> b) {
        if (a.isEmpty()) return b;
        if (b.isEmpty()) return a;
        return () -> new ConcatIterator(a, b);
    }

    private record ConcatIterator(Iterator<byte[]> firstIterator, Iterator<byte[]> secondIterator)
            implements Iterator<byte[]> {

        private ConcatIterator(List<byte[]> firstIterator, List<byte[]> secondIterator) {
            this(firstIterator.iterator(), secondIterator.iterator());
        }

        @Override
        public boolean hasNext() {
            return firstIterator.hasNext() || secondIterator.hasNext();
        }

        @Override
        public byte[] next() {
            return firstIterator.hasNext() ? firstIterator.next() : secondIterator.next();
        }
    }

    private record Keys(HmacKey hmacKey, DataEncryptionKey encKey) implements AutoCloseable {
        @Override
        public void close() {
            try { hmacKey.destroy(); } finally { encKey.destroy(); }
        }
    }
}
