/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines;

import static java.util.Objects.requireNonNull;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;

public final class X25519AuthKemState {
    final KeyPair privateKey;
    final List<PublicKey> publicKeys;
    final KeyPair ephemeralKeys;
    final DestroyableSecretKey demKey;
    final byte[] kdfSalt;

    X25519AuthKemState(KeyPair privateKey, List<PublicKey> publicKeys, KeyPair ephemeralKeys,
            DestroyableSecretKey demKey, byte[] kdfSalt) {
        this.privateKey = requireNonNull(privateKey, "private keys");
        this.publicKeys = requireNonNull(publicKeys, "public keys");
        this.ephemeralKeys = requireNonNull(ephemeralKeys, "ephemeral keys");
        this.demKey = requireNonNull(demKey, "DEM key");
        this.kdfSalt = requireNonNull(kdfSalt, "KDF salt");

        if (publicKeys.isEmpty() || publicKeys.size() > 65535) {
            throw new IllegalArgumentException("Must be at least 1 and at most 65535 public keys");
        }
    }
}
