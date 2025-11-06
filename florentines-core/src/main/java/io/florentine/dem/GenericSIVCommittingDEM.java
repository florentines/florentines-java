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
import io.florentine.crypto.StreamCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

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

    private final ThreadLocal<Mac> macThreadLocal;
    private final ThreadLocal<StreamCipher> cipherThreadLocal;
    private final byte[] kdfContext;
    private final int keyLen;
    private final String macAlgorithm;

    GenericSIVCommittingDEM(String identifier, String macAlgorithm, Supplier<StreamCipher> streamCipherSupplier) {
        super(identifier);
        this.macAlgorithm = requireNonNull(macAlgorithm, "macAlgorithm");

        this.macThreadLocal = threadLocal(() -> Mac.getInstance(macAlgorithm));
        this.cipherThreadLocal = ThreadLocal.withInitial(streamCipherSupplier);

        var tagLenBytes = macThreadLocal.get().getMacLength();
        this.keyLen = tagLenBytes / 2;
        assert keyLen >= 16;

        this.kdfContext = ("Florentine-DEM-" + identifier + "-SubKeys").getBytes(US_ASCII);
    }

    AlgorithmParameterSpec iv(byte[] siv) {
        return new IvParameterSpec(siv);
    }

    @Override
    KeyAndTag encapsulate(DataKey key, List<byte[]> publicData, List<byte[]> secretData) {
        var keyMaterial = validateAndExpandKey(key);
        var cipher = cipherThreadLocal.get();
        try (var macKey = new DataKey(keyMaterial, 0, keyLen, macAlgorithm);
             var encKey = cipher.importKey(keyMaterial, keyLen, keyLen)) {

            var tag = cascade(macKey, publicData, secretData);
            var siv = Arrays.copyOfRange(tag, keyLen, keyLen + SIV_LEN_BYTES);

            cipher.init(encKey, siv);
            for (var buffer : secretData) {
                cipher.encipher(buffer);
            }
            // Encrypt the tag to prevent length extension
            cipher.encipher(tag, 0, keyLen);
            return new KeyAndTag(new DataKey(tag, 0, keyLen, getIdentifier()), siv);
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
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
        var cipher = cipherThreadLocal.get();
        var keyMaterial = validateAndExpandKey(key);
        try (var macKey = new DataKey(keyMaterial, 0, keyLen, macAlgorithm);
             var encKey = cipher.importKey(keyMaterial, keyLen, keyLen)) {

            cipher.init(encKey, siv);
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

        } catch (GeneralSecurityException e) {
            CryptoUtils.wipe(secretData.toArray(byte[][]::new));
            log.debug("Error during decapsulation", e);
            throw new AssertionError(e);
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
        return hmac(key, kdfContext);
    }

    @SuppressWarnings("resource")
    private byte[] cascade(DataKey key, List<byte[]> publicData, List<byte[]> secretData)
            throws InvalidKeyException, NoSuchAlgorithmException {
        assert !publicData.isEmpty() || !secretData.isEmpty();

        byte[] tag = null;
        for (var data : List.of(publicData, secretData)) {
            for (var datum : data) {
                tag = hmac(key, datum);
                key.destroy();
                key = new DataKey(tag, 0, keyLen, macAlgorithm);
            }
        }
        assert tag != null;
        return tag;
    }

    private byte[] hmac(DataKey key, byte[] data) {
        var hmac = macThreadLocal.get();
        try {
            hmac.init(key);
            return hmac.doFinal(data);
        } catch (InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    private static <T> ThreadLocal<T> threadLocal(Callable<T> supplier) {
        return ThreadLocal.withInitial(() -> {
            try {
                return supplier.call();
            } catch (Exception e) {
                throw new UnsupportedOperationException(e);
            }
        });
    }
}
