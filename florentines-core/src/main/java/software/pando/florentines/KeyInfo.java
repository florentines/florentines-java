/*
 * Copyright 2022 Neil Madden.
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

package software.pando.florentines;

import static java.util.Objects.requireNonNull;

import java.security.Key;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Optional;

import software.pando.crypto.nacl.Crypto;

public class KeyInfo {
    private final Key secretKey;
    private final PublicKey publicKey;
    private final Algorithm algorithm;
    private final String subjectIdentifier;

    public KeyInfo(Key secretKey, PublicKey publicKey, Algorithm algorithm, String subjectIdentifier) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
        this.algorithm = requireNonNull(algorithm, "algorithm");
        this.subjectIdentifier = subjectIdentifier;
    }

    public String getSubjectIdentifier() {
        return subjectIdentifier;
    }

    public Optional<Key> getSecretKey() {
        return Optional.ofNullable(secretKey);
    }

    public Optional<PublicKey> getPublicKey() {
        return Optional.ofNullable(publicKey);
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public byte[] getKeyId(byte[] salt) {
        byte[] keyData = getPublicKey().map(Key::getEncoded)
                .or(() -> getSecretKey().map(Key::getEncoded))
                .orElseThrow();
        return Arrays.copyOf(Crypto.auth(Crypto.authKey(salt), keyData), 4);
    }

    @Override
    public String toString() {
        return "KeyInfo{" +
                "algorithm=" + algorithm +
                ", subjectIdentifier='" + subjectIdentifier + '\'' +
                ", publicKey=" + publicKey +
                '}';
    }
}
