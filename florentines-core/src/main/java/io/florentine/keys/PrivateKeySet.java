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

package io.florentine.keys;

import static java.util.Objects.requireNonNull;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import io.florentine.CryptoSuite;
import io.florentine.keys.PublicKeySet.PublicKeyInfo;

public record PrivateKeySet(String application, byte[] contextInfo, List<PrivateKeyInfo> keys) implements KeySet {
    public PrivateKeySet {
        requireNonNull(application, "application");
        requireNonNull(keys, "private keys");
        requirePrintableAscii(application);
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("No private keys supplied");
        }
        keys = List.copyOf(keys); // Defensive copy to ensure immutability
        contextInfo = requireNonNull(contextInfo, "context info").clone();
    }

    public byte[] contextInfo() {
        return contextInfo.clone();
    }

    public PrivateKeyInfo primary() {
        return keys.get(0);
    }

    public PublicKeySet toPublicKeySet() {
        var pks = keys.stream()
                .map(sk -> new PublicKeyInfo(sk.algorithm(), sk.publicKey()))
                .toList();
        return new PublicKeySet(application, contextInfo, pks);
    }

    public record PrivateKeyInfo(CryptoSuite algorithm, PrivateKey privateKey, PublicKey publicKey) {
        public PrivateKeyInfo {
            requireNonNull(algorithm, "algorithm");
            requireNonNull(privateKey, "private key");
            requireNonNull(publicKey, "public key");
        }
    }

    static void requirePrintableAscii(String str) {
        if (!str.chars().allMatch(i -> i >= 32 && i < 127)) {
            throw new IllegalArgumentException("Application identifier must be printable ASCII");
        }
    }
}
