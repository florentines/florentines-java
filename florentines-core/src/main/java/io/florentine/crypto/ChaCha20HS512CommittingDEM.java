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

package io.florentine.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.US_ASCII;

final class ChaCha20HS512CommittingDEM extends CommittingDEM {
    private static final String MAC_ALGORITHM = "HmacSHA512";
    private static final String CIPHER_ALGORITHM = "ChaCha20";

    ChaCha20HS512CommittingDEM() {
        super("CC20SIV-HS512");
    }

    @Override
    EncapsulatedData encapsulate(SecretKey demKey, List<Record> records) {
        try (var subKeys = deriveKeys(demKey)) {

            var mac = Mac.getInstance(MAC_ALGORITHM);
            var nextKey = cascade(mac, subKeys.macKey, records);
            var siv = finalize(mac, subKeys.finKey, nextKey.getKeyBytes());

            var cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, subKeys.encKey, new ChaCha20ParameterSpec(siv, 0));
            records.forEach(record -> encryptInPlace(cipher, record));

            return new EncapsulatedData(siv, nextKey);

        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    Optional<DestroyableSecretKey> decapsulate(SecretKey demKey, List<Record> records, byte[] tag) {
        return Optional.empty();
    }

    private static byte[] finalize(Mac mac, SecretKey finalizationKey, byte[] tag) throws InvalidKeyException {
        mac.init(finalizationKey);
        return Arrays.copyOf(mac.doFinal(tag), 12);
    }

    private static void encryptInPlace(Cipher cipher, Record record) {
        var data = record.secretContent();
        try {
            int bytes = cipher.update(data, 0, data.length, data);
            assert bytes == data.length;
        } catch (ShortBufferException e) {
            throw new AssertionError(e);
        }
    }

    private static DestroyableSecretKey cascade(Mac prf, DestroyableSecretKey macKey, Iterable<Record> records)
            throws GeneralSecurityException {
        var buffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        for (var record : records) {
            prf.init(macKey);
            macKey.destroy();
            prf.update(record.context());
            prf.update(record.publicContent());
            prf.update(record.secretContent());
            buffer.rewind().putInt(record.context().length).putInt(record.publicContent().length);
            prf.update(buffer.flip());
            macKey = new DestroyableSecretKey(prf.doFinal(), 0, 32, prf.getAlgorithm());
        }
        return macKey;
    }

    private static DataKeys deriveKeys(SecretKey demKey) {
        var keyMaterial = HKDF.expand(demKey, "Florentine-DEM-CC20SIV-HS512-SubKeys".getBytes(US_ASCII), 32*3);
        try {
            return new DataKeys(
                    new DestroyableSecretKey(keyMaterial, 0, 32, CIPHER_ALGORITHM),
                    new DestroyableSecretKey(keyMaterial, 32, 32, MAC_ALGORITHM),
                    new DestroyableSecretKey(keyMaterial, 64, 32, MAC_ALGORITHM)
            );
        } finally {
            Arrays.fill(keyMaterial, (byte) 0);
        }
    }

    private record DataKeys(DestroyableSecretKey encKey, DestroyableSecretKey macKey, DestroyableSecretKey finKey)
            implements AutoCloseable {
        @Override
        public void close() {
            encKey.destroy();
            macKey.destroy();
            finKey.destroy();
        }
    }
}
