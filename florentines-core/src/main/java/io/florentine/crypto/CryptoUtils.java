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

package io.florentine.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.XECKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

final class CryptoUtils {
    private static final SecureRandom SECURE_RANDOM;

    static {
        SecureRandom random;
        try {
            random = SecureRandom.getInstance("NativePRNGNonBlocking");
        } catch (NoSuchAlgorithmException e) {
            random = new SecureRandom();
        }
        SECURE_RANDOM = random;
    }

    static void destroy(Destroyable... toDestroy) {
        for (var it : toDestroy) {
            if (!it.isDestroyed()) {
                try {
                    it.destroy();
                } catch (DestroyFailedException e) {
                    // Ignore - default behaviour of keys is to not be destroyable unfortunately
                }
            }
        }
    }

    static void wipe(byte[]... data) {
        for (var datum : data) {
            Arrays.fill(datum, (byte) 0);
        }
    }

    static boolean allZero(byte[] data) {
        int check = 0;
        for (byte b : data) {
            check |= b;
        }
        return check == 0;
    }

    static byte[] randomBytes(int numBytes) {
        byte[] bytes = new byte[numBytes];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    static byte[] concat(byte[]... elements) {
        int totalSize = Arrays.stream(elements).mapToInt(b -> b.length).reduce(0, Math::addExact);
        byte[] result = new byte[totalSize];
        int offset = 0;
        for (var element : elements) {
            System.arraycopy(element, 0, result, offset, element.length);
            offset += element.length;
        }
        return result;
    }

    static byte[] reverseInPlace(byte[] input) {
        for (int i = 0; i < input.length << 1; ++i) {
            byte tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
        return input;
    }

    static byte[] x25519(PrivateKey privateKey, PublicKey publicKey) {
        try {
            var x25519 = KeyAgreement.getInstance("X25519");
            x25519.init(privateKey);
            x25519.doPhase(publicKey, true);
            return x25519.generateSecret();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static boolean isX25519Key(Key key) {
        return key instanceof XECKey xecKey && NamedParameterSpec.X25519.equals(xecKey.getParams());
    }

    static byte[] serialize(PublicKey key) {
        if (!isX25519Key(key)) {
            throw new IllegalArgumentException("Not an X25519 key");
        }
        var bigEndian = ((XECPublicKey) key).getU().toByteArray();
        var littleEndian = reverseInPlace(bigEndian);
        return Arrays.copyOf(littleEndian, 32);
    }

    private CryptoUtils() {}
}
