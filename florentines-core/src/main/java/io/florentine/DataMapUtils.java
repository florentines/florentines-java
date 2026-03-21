/*
 * Copyright 2026 Neil Madden.
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
import org.msgpack.value.ValueType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class DataMapUtils {

    static void writeTo(DataMap map, OutputStream out) throws IOException {
        try (var packer = MessagePack.newDefaultPacker(out)) {
            packer.packMapHeader(map.size());
            for (var field : map.entrySet()) {
                packer.packString(field.getKey());
                switch (field.getValue()) {
                    case Boolean b -> packer.packBoolean(b);
                    case Long l -> packer.packLong(l);
                    case String s -> packer.packString(s);
                    case DataMap.ByteArray b -> {
                        packer.packBinaryHeader(b.data().length);
                        packer.addPayload(b.data());
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

    static byte[] toBytes(DataMap map) {
        try (var out = new ByteArrayOutputStream()) {
            writeTo(map, out);
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
            var builder = DataMap.builder();
            for (int i = 0; i < size; ++i) {
                var key = unpacker.unpackString();
                var value = unpacker.unpackValue();
                switch (value.getValueType()) {
                    case ValueType.BOOLEAN -> builder.put(key, value.asBooleanValue().getBoolean());
                    case ValueType.INTEGER -> builder.put(key, value.asIntegerValue().asLong());
                    case ValueType.STRING -> builder.put(key, value.asStringValue().asString());
                    case ValueType.BINARY -> builder.put(key, value.asBinaryValue().asByteArray());
                    case ValueType.ARRAY -> {
                        var array = new ArrayList<String>(value.asArrayValue().size());
                        for (var element : value.asArrayValue()) {
                            array.add(element.asStringValue().asString());
                        }
                        builder.put(key, array);
                    }
                    case ValueType.MAP -> {
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

    private DataMapUtils() {}
}
