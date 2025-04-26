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

package io.florentine.crypto;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public final class AlgorithmRegistry {
    private final Map<String, ? extends Identifiable> registry = new ConcurrentHashMap<>();

    private <T extends Identifiable> Optional<T> get(String identifier, Class<T> type) {
        return Optional.ofNullable(registry.get(identifier))
                .filter(type::isInstance)
                .map(type::cast);
    }

    public Optional<KEM> getKem(String identifier) {
        return get(identifier, KEM.class);
    }

    public Optional<CommittingDEM> getDem(String identifier) {
        return get(identifier, CommittingDEM.class);
    }

    @Override
    public String toString() {
        return "AlgorithmRegistry{registeredAlgorithms=" + registry.keySet() + '}';
    }
}
