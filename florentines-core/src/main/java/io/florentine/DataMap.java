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

import org.msgpack.core.MessagePack;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
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

    public void writeTo(OutputStream out) throws IOException {
        try (var packer = MessagePack.newDefaultPacker(out)) {
            packer.packMapHeader(map.size());
            for (var field : map.entrySet()) {
                packer.packString(field.getKey());
                switch (field.getValue()) {
                    case Boolean b -> packer.packBoolean(b);
                    case Long l -> packer.packLong(l);
                    case String s -> packer.packString(s);
                    case ByteArray b -> {
                        packer.packBinaryHeader(b.data.length);
                        packer.addPayload(b.data);
                    }
                    case List<?> l -> {
                        packer.packArrayHeader(l.size());
                        for (var str : l) {
                            packer.packString((String) str);
                        }
                    }
                    case Map<?, ?> m -> {
                        packer.packMapHeader(m.size());
                        for (var entry : m.entrySet()) {
                            packer.packString((String) entry.getKey());
                            packer.packString((String) entry.getValue());
                        }
                    }
                    default -> throw new AssertionError("invalid value in map");
                }
            }
        }
    }

    public byte[] toBytes() {
        try (var out = new ByteArrayOutputStream()) {
            writeTo(out);
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize DataMap", e);
        }
    }

    public static Optional<DataMap> fromBytes(byte[] input) {
        try {
            return Optional.of(readFrom(new ByteArrayInputStream(input)));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    public static DataMap readFrom(InputStream in) throws IOException {
        try (var unpacker = MessagePack.newDefaultUnpacker(in)) {
            var size = unpacker.unpackMapHeader();
            var builder = builder();
            for (int i = 0; i < size; ++i) {
                var key = unpacker.unpackString();
                var value = unpacker.unpackValue();
                switch (value.getValueType()) {
                    case BOOLEAN -> builder.put(key, value.asBooleanValue().getBoolean());
                    case INTEGER -> builder.put(key, value.asIntegerValue().asLong());
                    case STRING -> builder.put(key, value.asStringValue().asString());
                    case BINARY -> builder.put(key, value.asBinaryValue().asByteArray());
                    case ARRAY -> {
                        var array = new ArrayList<String>(value.asArrayValue().size());
                        for (var element : value.asArrayValue()) {
                            array.add(element.asStringValue().asString());
                        }
                        builder.put(key, array);
                    }
                    case MAP -> {
                        var map = new LinkedHashMap<String, String>(value.asMapValue().size());
                        for (var entry : value.asMapValue().entrySet()) {
                            map.put(entry.getKey().asStringValue().asString(),
                                    entry.getValue().asStringValue().asString());
                        }
                        builder.put(key, map);
                    }
                    default -> throw new IOException("invalid DataMap binary data");
                }
            }
            return builder.build();
        }
    }

    public static class Builder {
        private final SortedMap<String, Object> map = new TreeMap<>();

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
    public boolean equals(Object o) {
        if (!(o instanceof DataMap dataMap)) {
            return false;
        }
        return Objects.equals(map, dataMap.map);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(map);
    }

    private record ByteArray(byte[] data) {
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
            return Arrays.toString(data);
        }
    }
}
