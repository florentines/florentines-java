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

import static io.florentine.keys.PrivateKeySet.requirePrintableAscii;
import static java.util.Objects.requireNonNull;

import java.security.PublicKey;
import java.util.List;

import io.florentine.CryptoSuite;

public record PublicKeySet(String application, byte[] contextInfo, List<PublicKeyInfo> keys) implements KeySet {
    public PublicKeySet {
        requireNonNull(application, "application");
        requireNonNull(keys, "keys");
        requirePrintableAscii(application);
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("No public keys provided");
        }
        keys = List.copyOf(keys);
        contextInfo = requireNonNull(contextInfo, "context info").clone();
    }

    public byte[] contextInfo() {
        return contextInfo.clone();
    }

    public record PublicKeyInfo(CryptoSuite algorithm, PublicKey pk) {
        public PublicKeyInfo {
            requireNonNull(algorithm, "algorithm");
            requireNonNull(pk, "public key");
        }
    }
}
