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

package io.florentine;

import org.msgpack.core.MessagePack;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.SortedMap;
import java.util.TreeMap;

import static java.util.Objects.requireNonNull;

public final class Headers {
    private final SortedMap<String, Value> headers;

    private Headers(Builder builder) {
        this.headers = Collections.unmodifiableSortedMap(builder.headers);
    }

    public static Builder builder() {
        return new Builder();
    }

    private Optional<Value> get(String key) {
        return Optional.ofNullable(headers.get(key));
    }

    public Optional<Boolean> getBoolean(String key) {
        return get(key).flatMap(value -> value.as(Value.Bool.class).map(Value.Bool::value));
    }

    public OptionalLong getLong(String key) {
        var value = headers.get(key);
        if (value instanceof Value.Long(long l)) {
            return OptionalLong.of(l);
        }
        return OptionalLong.empty();
    }

    public Optional<String> getString(String key) {
        return get(key).flatMap(value -> value.as(Value.Text.class).map(Value.Text::value));
    }

    public Optional<byte[]> getBytes(String key) {
        return get(key).flatMap(value -> value.as(Value.Bytes.class).map(Value.Bytes::value));
    }

    public Optional<Map<String, String>> getMap(String key) {
        return get(key).flatMap(value -> value.as(Value.Map.class).map(Value.Map::value));
    }

    public Optional<List<String>> getArray(String key) {
        return get(key).flatMap(value -> value.as(Value.Array.class).map(Value.Array::value));
    }

    public byte[] toBytes() {
        try (var packer = MessagePack.newDefaultBufferPacker()) {
            packer.packMapHeader(headers.size());
            headers.forEach((key, value) -> {
                try {
                    packer.packString(key);
                    switch (value) {
                        case Value.Bool b -> packer.packBoolean(b.value);
                        case Value.Long l -> packer.packLong(l.value);
                        case Value.Text t -> packer.packString(t.value);
                        case Value.Bytes b -> {
                            packer.packBinaryHeader(b.value.length);
                            packer.addPayload(b.value);
                        }
                        case Value.Array a -> {
                            packer.packArrayHeader(a.value.size());
                            for (var str : a.value) {
                                packer.packString(str);
                            }
                        }
                        case Value.Map m -> {
                            packer.packMapHeader(m.value.size());
                            for (var entry : m.value.entrySet()) {
                                packer.packString(entry.getKey());
                                packer.packString(entry.getValue());
                            }
                        }
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            return packer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static class Builder {
        private final SortedMap<String, Value> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        private Builder put(String key, Value value) {
            var old = headers.putIfAbsent(requireNonNull(key, "key"), requireNonNull(value, "value"));
            if (old != null && !old.equals(value)) {
                throw new IllegalStateException("header already set: " + key);
            }
            return this;
        }

        public Builder header(String key, boolean value) {
            return put(key, new Value.Bool(value));
        }

        public Builder header(String key, String value) {
            return put(key, new Value.Text(value));
        }

        public Builder header(String key, long value) {
            return put(key, new Value.Long(value));
        }

        public Builder header(String key, byte[] value) {
            return put(key, new Value.Bytes(value));
        }

        public Builder header(String key, Map<String, String> value) {
            return put(key, new Value.Map(value));
        }

        public Builder header(String key, List<String> value) {
            return put(key, new Value.Array(value));
        }

        public Headers build() {
            return new Headers(this);
        }
    }

    private sealed interface Value {
        record Bool(boolean value) implements Value {}
        record Text(String value) implements Value {
            public Text {
                requireNonNull(value);
            }
        }
        record Long(long value) implements Value {}
        record Bytes(byte[] value) implements Value {
            public Bytes {
                requireNonNull(value);
            }
        }
        record Map(java.util.Map<String, String> value) implements Value {
            public Map {
                requireNonNull(value);
            }
        }
        record Array(List<String> value) implements Value {
            public Array {
                requireNonNull(value);
            }
        }

        default <T extends Value> Optional<T> as(Class<T> type) {
            if (type.isInstance(this)) {
                return Optional.of(type.cast(this));
            }
            return Optional.empty();
        }
    }
}
