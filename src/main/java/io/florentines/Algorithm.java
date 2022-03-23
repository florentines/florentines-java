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

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import io.florentines.ConversationState.Deserializer;
import io.florentines.X25519AuthenticatedKem.State;

/**
 * A Florentine algorithm suite consists of three parts:
 * <ul>
 *     <li>A Key Encapsulation Mechanism (KEM) that produces a unique data encryption key for each message along
 *     with an encapsulation of that key that can be decrypted by one or more specified recipients. Florentine KEMs
 *     are authenticated multi-recipient Tag-KEMs.</li>
 *     <li>A Data Encapsulation Mechanism (DEM) that encrypts and authenticates the original message content of the
 *     Florentine.</li>
 *     <li>A secure pseudorandom function (PRF), which is used to append caveats to an existing Florentine.</li>
 * </ul>
 */
public final class Algorithm {
    private static final AesHmacSivDem A256SIV_HS256 = new AesHmacSivDem();
    private static final Map<String, Algorithm> algorithms = new ConcurrentHashMap<>();

    public static final Algorithm AUTHKEM_X25519_HKDF_A256SIV_HS256 = register(
            new Algorithm(new X25519AuthenticatedKem(A256SIV_HS256), A256SIV_HS256, PRF.HS256,
                    State::readFrom));

    final KEM kem;
    final DEM dem;
    final PRF prf;
    private final Deserializer deserializer;

    private Algorithm(KEM kem, DEM dem, PRF prf, Deserializer deserializer) {
        this.kem = kem;
        this.dem = dem;
        this.prf = prf;
        this.deserializer = deserializer;
    }

    public String getIdentifier() {
        return "Florentine-" + kem.getIdentifier();
    }

    public PrivateIdentity generateKeys(String application, String subject) {
        return kem.generateKeys(application, subject);
    }

    public Optional<ConversationState> readReplyStateFrom(InputStream in) throws IOException {
        return deserializer.readFrom(in);
    }

    public static Algorithm register(Algorithm algorithm) {
        Algorithm prev = algorithms.putIfAbsent(algorithm.getIdentifier(), algorithm);
        return prev != null ? prev : algorithm;
    }

    public static Optional<Algorithm> get(String identifier) {
        return Optional.ofNullable(algorithms.get(identifier));
    }

    @Override
    public String toString() {
        return getIdentifier();
    }
}
