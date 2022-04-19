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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class CaveatValue {

    private final Object value;

    CaveatValue(Object value) {
        this.value = requireNonNull(value, "value");
    }

    public Optional<Long> asLong() {
        return expect(Number.class).map(Number::longValue);
    }

    public Optional<String> asString() {
        return expect(String.class);
    }

    public Optional<List<String>> asListOfStrings() {
        return asList(String.class);
    }

    @SuppressWarnings("unchecked")
    public <T> Optional<List<T>> asList(Class<T> elementType) {
        return expect(List.class)
                .map(xs -> (List<T>) xs)
                .filter(xs -> xs.stream().allMatch(elementType::isInstance));
    }

    public Optional<List<?>> asList() {
        return expect(List.class).map(xs -> (List<?>) xs);
    }

    public Optional<byte[]> asByteArray() {
        return expect(byte[].class);
    }

    public Optional<Map<String, CaveatValue>> asMap() {
        return expect(Map.class)
                .map(m -> (Map<String, ?>) m)
                .map(map -> {
                    var copy = new LinkedHashMap<String, CaveatValue>(map.size());
                    map.forEach((key, value) -> copy.put(key, new CaveatValue(value)));
                    return copy;
                });
    }

    private <T> Optional<T> expect(Class<T> type) {
        if (type.isInstance(value)) {
            return Optional.of(type.cast(value));
        }
        return Optional.empty();
    }
}
