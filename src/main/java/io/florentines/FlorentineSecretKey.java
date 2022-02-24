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

import java.util.Optional;
import java.util.function.Function;

public final class FlorentineSecretKey<KeyType> {
    private final KeyType secretKey;
    private final Function<KeyType, Optional<byte[]>> secretKeyExtractor;
    private final FlorentinePublicKey publicKey;

    public FlorentineSecretKey(KeyType secretKey, Function<KeyType, Optional<byte[]>> secretKeyExtractor,
            FlorentinePublicKey publicKey) {
        this.secretKey = secretKey;
        this.secretKeyExtractor = secretKeyExtractor;
        this.publicKey = publicKey;
    }

    KeyType getSecretKey() {
        return secretKey;
    }

    public FlorentinePublicKey getPublicKey() {
        return publicKey;
    }

    public Optional<byte[]> getSecretKeyMaterial() {
        return secretKeyExtractor.apply(secretKey);
    }
}
