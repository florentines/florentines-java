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

package io.florentine.kem;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Collection;
import java.util.Optional;

public final class X25519AuthKEM extends AuthKEM {
    X25519AuthKEM() {
        super("AuthKEM-X25519");
    }

    @Override
    public Optional<PublicKey> decodePublicKey(byte[] pk) {
        if (pk == null) {
            return Optional.empty();
        }
        try {
            var keyFactory = KeyFactory.getInstance("X25519");
            return Optional.of(keyFactory.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u(pk))));
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        } catch (InvalidKeySpecException e) {
            return Optional.empty();
        }
    }

    @Override
    public KEMState begin(LocalParty localParty, Collection<RemoteParty> remoteParties) {
        return null;
    }

    private static BigInteger u(byte[] littleEndian) {
        var bigEndian = new byte[littleEndian.length];
        for (int i = 0; i < littleEndian.length; ++i) {
            bigEndian[bigEndian.length - i - 1] = littleEndian[i];
        }
        return new BigInteger(1, bigEndian);
    }
}
