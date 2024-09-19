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

import static io.florentine.CC20HS512.hmac;
import static io.florentine.Utils.threadLocal;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import javax.crypto.KeyAgreement;

final class X25519Kem extends KEM {
    private static final ThreadLocal<KeyAgreement> X25519 = threadLocal(() -> KeyAgreement.getInstance("X25519"));

    @Override
    public String identifier() {
        return "AuthKEM-X25519";
    }

    @Override
    KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    @Override
    byte[] keyId(byte[] salt, PublicKey publicKey) {
        if (publicKey instanceof XECPublicKey xpk &&
                "X25519".equals(((NamedParameterSpec) xpk.getParams()).getName())) {
            return hmac(salt, Utils.unsignedLittleEndian(xpk.getU()));
        } else {
            throw new IllegalArgumentException("Invalid public key");
        }
    }

    @Override
    State begin(DEM dem, KeySet local, Collection<KeySet> remote) {
        return null;
    }

    private static void validateKeys(KeySet local, Collection<KeySet> remote) {
        var app = local.getApplication();
        if (!remote.stream().allMatch(ks -> ks.getApplication().equals(app))) {
            throw new IllegalArgumentException("KeySet applications don't match");
        }
    }

    private static byte[] x25519(Key secretKey, PublicKey publicKey) {
        var x25519 = X25519.get();
        try {
            x25519.init(secretKey);
            x25519.doPhase(publicKey, true);
            return x25519.generateSecret();
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static final class State implements KEM.State {
        private final KeyPair localKeys;
        private final KeyPair ephemeralKeys;
        private final List<PublicKey> remoteKeys;
        private final byte[] salt;
        private final DEM dem;
        private final DataEncapsulationKey demKey;

        private State(DEM dem, KeyPair localKeys, KeyPair ephemeralKeys, List<PublicKey> remoteKeys, byte[] salt) {
            this.localKeys = localKeys;
            this.ephemeralKeys = ephemeralKeys;
            this.remoteKeys = remoteKeys;
            this.salt = salt;
            this.dem = dem;
            this.demKey = dem.generateKey();
        }

        @Override
        public DataEncapsulationKey key() {
            return null;
        }

        @Override
        public EncapsulatedKey encapsulate(byte[] context) {
            return null;
        }

        @Override
        public Optional<DecapsulatedKey> decapsulate(byte[] encapsulatedKey, byte[] context) {
            return Optional.empty();
        }
    }
}
