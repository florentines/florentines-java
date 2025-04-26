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

package io.florentine.model;

import org.msgpack.value.ImmutableValue;
import org.msgpack.value.ValueFactory;
import org.msgpack.value.ValueType;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.TreeMap;
import java.util.function.Function;

import static java.util.stream.Collectors.toUnmodifiableMap;

public final class Headers {
    private final Map<String, ? extends ImmutableValue> headers;

    private Headers(Map<String, ? extends ImmutableValue> headers) {
        this.headers = Map.copyOf(headers);
    }

    public static Builder builder() {
        return new Builder();
    }

    private <T> Optional<T> getHeader(String name, ValueType type,
                                                    Function<? super ImmutableValue, T> converter) {
        return Optional.ofNullable(headers.get(name))
                .filter(value -> value.getValueType() == type)
                .map(converter);
    }

    public Optional<String> getString(String name) {
        return getHeader(name, ValueType.STRING, value -> value.asStringValue().asString());
    }

    public Optional<Long> getInteger(String name) {
        return getHeader(name, ValueType.INTEGER, value -> value.asIntegerValue().asLong());
    }

    public Optional<Boolean> getBoolean(String name) {
        return getHeader(name, ValueType.BOOLEAN, value -> value.asBooleanValue().getBoolean());
    }

    public Optional<byte[]> getBytes(String name) {
        return getHeader(name, ValueType.BINARY, value -> value.asBinaryValue().asByteArray());
    }

    public Optional<List<String>> getListOfStrings(String name) {
        return getHeader(name, ValueType.ARRAY, value -> value.asArrayValue().list()
                .stream().map(item -> item.asStringValue().asString()).toList());
    }

    public Optional<Map<String, String>> getMapOfStrings(String name) {
        return getHeader(name, ValueType.MAP, value -> value.asMapValue().map().entrySet().stream()
                .collect(toUnmodifiableMap(
                        entry -> entry.getKey().asStringValue().asString(),
                        entry -> entry.getValue().asStringValue().asString())));
    }

    public static final class Builder {
        private final Map<String, ImmutableValue> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        private Builder header(String headerName, ImmutableValue value) {
            var old = headers.putIfAbsent(headerName, value);
            if (old != null && !old.equals(value)) {
                throw new IllegalStateException("Header has already been set");
            }
            return this;
        }

        public Builder header(String name, String value) {
            return header(name, ValueFactory.newString(value));
        }

        public Builder header(String name, long value) {
            return header(name, ValueFactory.newInteger(value));
        }

        public Builder header(String name, boolean value) {
            return header(name, ValueFactory.newBoolean(value));
        }

        public Builder header(String name, byte[] value) {
            return header(name, ValueFactory.newBinary(value));
        }

        public Builder header(String name, List<String> value) {
            return header(name, ValueFactory.newArray(value.stream().map(ValueFactory::newString).toList()));
        }

        @SuppressWarnings("unchecked")
        public Builder header(String name, Map<String, String> values) {
            var entries = values.entrySet().stream()
                    .map(entry -> ValueFactory.newMapEntry(
                            ValueFactory.newString(entry.getKey()), ValueFactory.newString(entry.getValue())))
                    .toArray(Entry[]::new);
            return header(name, ValueFactory.newMap(entries).immutableValue());
        }

        public Headers build() {
            return new Headers(headers);
        }
    }
}
