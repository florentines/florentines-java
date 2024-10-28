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

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

final class Registry<T extends Registry.Identifiable> {
    private final ConcurrentMap<String, T> registry = new ConcurrentHashMap<>();

    void register(T it) {
        var old = registry.putIfAbsent(it.identifier(), it);
        if (old != null && it != old) {
            throw new IllegalStateException("Identifier already registered");
        }
    }

    Optional<T> get(String identifier) {
        return Optional.ofNullable(registry.get(identifier));
    }

    interface Identifiable {
        String identifier();
    }
}
