package io.florentine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

final class A128SIV_HS256 extends CommittingDEM {
    static final CommittingDEM INSTANCE = new A128SIV_HS256();

    private static final Logger log = LoggerFactory.getLogger(A128SIV_HS256.class);
    private static final String HMAC_SHA_256 = "HmacSHA256";

    private A128SIV_HS256() {
        super("A128SIV-HS256");
    }

    @Override
    KeyAndTag encapsulate(DataKey key, List<byte[]> publicData, List<byte[]> secretData) {
        assert getIdentifier().equals(key.algorithm()) && key.keyMaterial().length == 16;
        var keyMaterial = sha256(key.keyMaterial());
        try (var macKey = new DataKey(keyMaterial, 0, 16, HMAC_SHA_256);
             var encKey = new DataKey(keyMaterial, 16, 32, "AES")) {

            var keyAndTag = cascade(macKey, publicData, secretData);
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(keyAndTag.tag()));
            for (var buffer : secretData) {
                int bytesEncrypted = cipher.update(buffer, 0, buffer.length, buffer);
                assert bytesEncrypted == buffer.length;
            }

            return keyAndTag;
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        } finally {
            CryptoUtils.wipe(keyMaterial);
        }
    }

    @Override
    Optional<DataKey> decapsulate(DataKey key, List<byte[]> publicData, List<byte[]> secretData, byte[] tag) {
        assert getIdentifier().equals(key.algorithm()) && key.keyMaterial().length == 16;
        var keyMaterial = sha256(key.keyMaterial());
        try (var macKey = new DataKey(keyMaterial, 0, 16, HMAC_SHA_256);
             var encKey = new DataKey(keyMaterial, 16, 32, "AES")) {

            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(tag));
            for (var buffer : secretData) {
                int bytesEncrypted = cipher.update(buffer, 0, buffer.length, buffer);
                assert bytesEncrypted == buffer.length;
            }

            var keyAndTag = cascade(macKey, publicData, secretData);
            if (MessageDigest.isEqual(tag, keyAndTag.tag())) {
                return Optional.of(keyAndTag.key());
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

    @SuppressWarnings("resource")
    private static KeyAndTag cascade(DataKey key, List<byte[]> publicData, List<byte[]> secretData)
            throws InvalidKeyException, NoSuchAlgorithmException {
        assert !publicData.isEmpty() || !secretData.isEmpty();

        var hmac = Mac.getInstance(HMAC_SHA_256);
        byte[] tag = null;
        for (var data : List.of(publicData, secretData)) {
            for (var datum : data) {
                hmac.init(key);
                tag = hmac.doFinal(datum);
                key.destroy();
                key = new DataKey(tag, 0, 16, HMAC_SHA_256);
            }
        }
        assert tag != null;
        return new KeyAndTag(key, Arrays.copyOfRange(tag, 16, 32));
    }

    private static byte[] sha256(byte[] input) {
        try {
            var hash = MessageDigest.getInstance("SHA-256");
            return hash.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e); // Mandatory algorithm
        }
    }
}
