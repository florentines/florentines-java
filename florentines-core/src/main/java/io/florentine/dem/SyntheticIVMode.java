/*
 * Copyright 2025 Neil Madden.
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

import io.florentine.crypto.CryptoUtils;
import io.florentine.crypto.DestroyableSecretKey;
import io.florentine.crypto.PseudoRandomFunction;
import io.florentine.crypto.StreamCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;

/**
 * A generic {@link CommittingDEM} implementation based on a combination of a committing pseudorandom function (PRF)
 * and a length-preserving stream cipher in a Synthetic IV (SIV) construction. To encapsulate a message, first the PRF
 * is used to compute a tag over the
 */
abstract class SyntheticIVMode extends CommittingDEM {
    private static final Logger log = LoggerFactory.getLogger(SyntheticIVMode.class);
    private static final int SIV_LEN_BYTES = 16;

    private final PseudoRandomFunction prf;
    private final StreamCipher streamCipher;
    private final byte[] kdfContext;
    private final int keyLen;

    SyntheticIVMode(String identifier, PseudoRandomFunction prf, StreamCipher streamCipher) {
        super(identifier);
        this.prf = prf;
        this.streamCipher = requireNonNull(streamCipher, "streamCipher");
        this.kdfContext = ("Florentine-DEM-" + identifier + "-SubKeys").getBytes(US_ASCII);
        this.keyLen = prf.tagLen() / 2;
    }

    @Override
    public KeyAndTag encapsulate(DestroyableSecretKey key, List<byte[]> publicData, List<byte[]> secretData) {
        if (publicData.isEmpty() && secretData.isEmpty()) {
            throw new IllegalArgumentException("no data specified");
        }
        try (var keys = validateAndExpandKey(key)) {

            var tag = prf.cascade(keys.prfKey, concat(publicData, secretData));
            var mid = tag.length / 2;
            var siv = Arrays.copyOfRange(tag, mid, mid + SIV_LEN_BYTES);

            var cipher = streamCipher.begin(keys.encKey, siv);
            secretData.forEach(cipher::encipher);

            // Encrypt the tag to prevent length extension
            cipher.encipher(tag, 0, mid);
            return new KeyAndTag(new DestroyableSecretKey(tag, 0, mid, getIdentifier()), siv);
        }
    }

    @Override
    public Optional<DestroyableSecretKey> decapsulate(DestroyableSecretKey key, List<byte[]> publicData, List<byte[]> secretData, byte[] siv) {
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

            var computedTag = prf.cascade(keys.prfKey, concat(publicData, secretData));

            if (MessageDigest.isEqual(siv, Arrays.copyOfRange(computedTag, keyLen, keyLen + SIV_LEN_BYTES))) {
                cipher.encipher(computedTag, 0, keyLen);
                return Optional.of(new DestroyableSecretKey(computedTag, 0, keyLen, getIdentifier()));
            } else {
                // Avoid releasing unverified plaintext
                CryptoUtils.wipe(secretData.toArray(byte[][]::new));
            }
        }
        return Optional.empty();
    }

    private Keys validateAndExpandKey(DestroyableSecretKey key) {
        if (key == null || !Objects.equals(getIdentifier(), key.getAlgorithm())
                || !"RAW".equals(key.getFormat()) || key.isDestroyed() || key.keyMaterial() == null
                || key.keyMaterial().length != keyLen) {
            throw new IllegalArgumentException("invalid key");
        }
        var keyMaterial = prf.process(key, kdfContext);
        try {
            return new Keys(prf.importKey(keyMaterial, 0), streamCipher.importKey(keyMaterial, keyLen));
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

    private record Keys(DestroyableSecretKey prfKey, DestroyableSecretKey encKey) implements AutoCloseable {
        @Override
        public void close() {
            try { prfKey.destroy(); } finally { encKey.destroy(); }
        }
    }
}
