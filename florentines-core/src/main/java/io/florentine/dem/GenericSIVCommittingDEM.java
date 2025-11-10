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

import io.florentine.CryptoUtils;
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
abstract class GenericSIVCommittingDEM extends CommittingDEM {
    private static final Logger log = LoggerFactory.getLogger(GenericSIVCommittingDEM.class);
    private static final int SIV_LEN_BYTES = 16;

    private final PseudoRandomFunction prf;
    private final StreamCipher streamCipher;
    private final byte[] kdfContext;
    private final int keyLen;

    GenericSIVCommittingDEM(String identifier, PseudoRandomFunction prf, StreamCipher streamCipher) {
        super(identifier);
        this.prf = prf;
        this.streamCipher = requireNonNull(streamCipher, "streamCipher");
        this.kdfContext = ("Florentine-DEM-" + identifier + "-SubKeys").getBytes(US_ASCII);
        this.keyLen = prf.tagLen() / 2;
    }

    @Override
    KeyAndTag encapsulate(DataKey key, List<byte[]> publicData, List<byte[]> secretData) {
        var keyMaterial = validateAndExpandKey(key);
        try (var macKey = prf.importKey(keyMaterial, 0);
             var encKey = streamCipher.importKey(keyMaterial, keyLen)) {

            var tag = cascade(macKey, publicData, secretData);
            var mid = tag.length / 2;
            var siv = Arrays.copyOfRange(tag, mid, mid + SIV_LEN_BYTES);

            var cipher = streamCipher.begin(encKey, siv);
            for (var buffer : secretData) {
                cipher.encipher(buffer);
            }
            // Encrypt the tag to prevent length extension
            cipher.encipher(tag, 0, mid);
            return new KeyAndTag(new DataKey(tag, 0, mid, getIdentifier()), siv);
        } finally {
            CryptoUtils.wipe(keyMaterial);
        }
    }

    @Override
    Optional<DataKey> decapsulate(DataKey key, List<byte[]> publicData, List<byte[]> secretData, byte[] siv) {
        if (siv.length != SIV_LEN_BYTES) {
            log.debug("Invalid SIV length {} - must be {} bytes", siv.length, SIV_LEN_BYTES);
            return Optional.empty();
        }
        var keyMaterial = validateAndExpandKey(key);
        try (var macKey = prf.importKey(keyMaterial, 0);
             var encKey = streamCipher.importKey(keyMaterial, macKey.to())) {
            var cipher = streamCipher.begin(encKey, siv);
            for (var buffer : secretData) {
                cipher.decipher(buffer);
            }
            var computedTag = cascade(macKey, publicData, secretData);
            if (MessageDigest.isEqual(siv, Arrays.copyOfRange(computedTag, keyLen, keyLen + SIV_LEN_BYTES))) {
                cipher.encipher(computedTag, 0, keyLen);
                return Optional.of(new DataKey(computedTag, 0, keyLen, getIdentifier()));
            } else {
                // Avoid releasing unverified plaintext
                CryptoUtils.wipe(secretData.toArray(byte[][]::new));
            }

        } finally {
            CryptoUtils.wipe(keyMaterial);
        }

        return Optional.empty();
    }

    private byte[] validateAndExpandKey(DataKey key) {
        if (key == null || !Objects.equals(getIdentifier(), key.getAlgorithm())
                || !"RAW".equals(key.getFormat()) || key.isDestroyed() || key.keyMaterial() == null
                || key.keyMaterial().length != keyLen) {
            throw new IllegalArgumentException("invalid key");
        }
        return prf.process(key, kdfContext);
    }

    private byte[] cascade(DataKey key, List<byte[]> publicData, List<byte[]> secretData) {
        assert !publicData.isEmpty() || !secretData.isEmpty();
        return prf.cascade(key, concat(publicData, secretData));
    }

    private static Iterable<byte[]> concat(List<byte[]> a, List<byte[]> b) {
        if (a.isEmpty()) return b;
        if (b.isEmpty()) return a;
        return () -> new ConcatIterator(a, b);
    }

    private static class ConcatIterator implements Iterator<byte[]> {
        private final Iterator<byte[]> firstIterator;
        private final Iterator<byte[]> secondIterator;

        ConcatIterator(List<byte[]> a, List<byte[]> b) {
            firstIterator = a.iterator();
            secondIterator = b.iterator();
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
}
