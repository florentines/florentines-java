/*
 * Copyright 2025-2026 Neil Madden.
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

import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import static java.util.Objects.requireNonNull;

public final class DataMap {
    private final SortedMap<String, Object> map;

    private DataMap(Builder builder) {
        this.map = Collections.unmodifiableSortedMap(builder.map);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static DataMap empty() {
        return builder().build();
    }

    public static DataMap of(String key, boolean value) {
        return builder().put(key, value).build();
    }

    public static DataMap of(String key, long value) {
        return builder().put(key, value).build();
    }

    public static DataMap of(String key, String value) {
        return builder().put(key, value).build();
    }

    public static DataMap of(String key, byte[] value) {
        return builder().put(key, value).build();
    }

    public static DataMap of(String key, List<String> value) {
        return builder().put(key, value).build();
    }

    public static DataMap of(String key, Map<String, String> value) {
        return builder().put(key, value).build();
    }

    public Builder copy() {
        return new Builder(new TreeMap<>(map));
    }

    public int size() {
        return map.size();
    }

    public boolean isEmpty() {
        return map.isEmpty();
    }

    Set<Map.Entry<String, Object>> entrySet() {
        return map.entrySet();
    }

    private <T> Optional<T> get(String key, Class<T> type) {
        var value = map.get(key);
        if (type.isInstance(value)) {
            return Optional.of(type.cast(value));
        }
        return Optional.empty();
    }

    public Optional<Boolean> getBoolean(String key) {
        return get(key, Boolean.class);
    }

    public OptionalLong getLong(String key) {
        var value = map.get(key);
        return value instanceof Long l ? OptionalLong.of(l) : OptionalLong.empty();
    }

    public Optional<String> getString(String key) {
        return get(key, String.class);
    }

    public Optional<byte[]> getBytes(String key) {
        return get(key, ByteArray.class).map(bytes -> bytes.data);
    }

    @SuppressWarnings("unchecked")
    public Optional<Map<String, String>> getMap(String key) {
        var value = map.get(key);
        if (value instanceof Map<?,?> m) {
            return Optional.of((Map<String, String>) m);
        }
        return Optional.empty();
    }

    @SuppressWarnings("unchecked")
    public Optional<List<String>> getList(String key) {
        var value = map.get(key);
        if (value instanceof List<?> m) {
            return Optional.of((List<String>) m);
        }
        return Optional.empty();
    }

    public static class Builder {
        final SortedMap<String, Object> map;

        Builder(SortedMap<String, Object> map) {
            this.map = map;
        }

        Builder() {
            this(new TreeMap<>());
        }

        private Builder put0(String key, Object value) {
            var old = map.putIfAbsent(requireNonNull(key, "key"), requireNonNull(value, "value"));
            if (old != null && !old.equals(value)) {
                throw new IllegalStateException("value already set: " + key);
            }
            return this;
        }

        public Builder put(String key, boolean value) {
            return put0(key, value);
        }

        public Builder put(String key, String value) {
            return put0(key, value);
        }

        public Builder put(String key, long value) {
            return put0(key, value);
        }

        public Builder put(String key, byte[] value) {
            return put0(key, new ByteArray(value));
        }

        public Builder put(String key, Map<String, String> value) {
            return put0(key, value);
        }

        public Builder put(String key, List<String> value) {
            return put0(key, value);
        }

        public DataMap build() {
            return new DataMap(this);
        }
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof DataMap that && Objects.equals(this.map, that.map);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(map);
    }

    @Override
    public String toString() {
        return map.toString();
    }

    record ByteArray(byte[] data) {
        ByteArray {
            data = data.clone(); // defensive copy
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof ByteArray that && Arrays.equals(this.data, that.data);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }

        @Override
        public String toString() {
            return "byte[" + HexFormat.of().formatHex(data) + "]";
        }
    }
}
