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

package io.florentine.data;

import com.grack.nanojson.JsonParserException;
import com.grack.nanojson.JsonReader;
import io.florentine.Base64url;

import java.io.IOException;
import java.io.InputStream;

import static java.util.Objects.requireNonNull;

public final class JsonDataReader implements DataReader {
    private final JsonReader reader;
    private final InputStream inputStream;

    public JsonDataReader(InputStream in) throws IOException {
        try {
            this.inputStream = requireNonNull(in);
            this.reader = JsonReader.from(in);
        } catch (JsonParserException e) {
            throw new IOException(e);
        }
    }

    @Override
    public boolean readBool() throws IOException {
        try {
            return reader.bool();
        } catch (JsonParserException e) {
            throw new IOException(e);
        }
    }

    @Override
    public double readNum() throws IOException {
        try {
            return reader.doubleVal();
        } catch (JsonParserException e) {
            throw new IOException(e);
        }
    }

    @Override
    public long readInt() throws IOException {
        try {
            return reader.longVal();
        } catch (JsonParserException e) {
            throw new IOException(e);
        }
    }

    @Override
    public String readText() throws IOException {
        try {
            return reader.string();
        } catch (JsonParserException e) {
            throw new IOException(e);
        }
    }

    @Override
    public byte[] readBytes() throws IOException {
        return Base64url.decode(readText());
    }

    @Override
    public Rank1Array readRank1Array() throws IOException {
        try {
            var result = Rank1Array.of();
            reader.array();
            while (reader.next()) {
                switch (reader.current()) {
                    case BOOLEAN -> result.add(reader.bool());
                    case NUMBER -> {
                        var doubleVal = reader.doubleVal();
                        if (doubleVal == (long)doubleVal) {
                            result.add((long) doubleVal);
                        } else {
                            result.add(doubleVal);
                        }
                    }
                    case STRING -> {
                        var str = reader.string();
                        try {
                            // If it decodes as base64url then assume binary
                            result.add(Base64url.decode(str));
                        } catch (IllegalArgumentException ex) {
                            result.add(str);
                        }
                    }
                    default -> throw new IOException("invalid type: " + reader.current());
                }
            }
            return result;
        } catch (JsonParserException e) {
            throw new IOException(e);
        }
    }

    @Override
    public Rank1Map readRank1Map() throws IOException {
        try {
            var result = new Rank1Map();
            reader.object();
            while (reader.next()) {
                var key = reader.key();
                switch (reader.current()) {
                    case BOOLEAN -> result.put(key, reader.bool());
                    case NUMBER -> result.put(key, reader.doubleVal());
                    case STRING -> {
                        var str = reader.string();
                        try {
                            // If it decodes as base64url then assume binary
                            result.put(key, Base64url.decode(str));
                        } catch (IllegalArgumentException ex) {
                            result.put(key, str);
                        }
                    }
                    default -> throw new IOException("invalid type: " + reader.current());
                }
            }
            return result;
        } catch (JsonParserException e) {
            throw new IOException(e);
        }
    }

    @Override
    public Rank2Array readRank2Array() throws IOException {
        try {
            var result = Rank2Array.of();
            reader.array();
            while (reader.next()) {
                switch (reader.current()) {
                    case BOOLEAN -> result.add(reader.bool());
                    case NUMBER -> result.add(reader.doubleVal());
                    case STRING -> {
                        var str = reader.string();
                        try {
                            // If it decodes as base64url then assume binary
                            result.add(Base64url.decode(str));
                        } catch (IllegalArgumentException ex) {
                            result.add(str);
                        }
                    }
                    case ARRAY -> result.add(readRank1Array());
                    case OBJECT -> result.add(readRank1Map());
                    default -> throw new IOException("invalid type: " + reader.current());
                }
            }
            return result;
        } catch (JsonParserException e) {
            throw new IOException(e);
        }
    }

    @Override
    public Rank2Map readRank2Map() throws IOException {
        try {
            var result = new Rank2Map();
            reader.object();
            while (reader.next()) {
                var key = reader.key();
                switch (reader.current()) {
                    case BOOLEAN -> result.put(key, reader.bool());
                    case NUMBER -> result.put(key, reader.doubleVal());
                    case STRING -> {
                        var str = reader.string();
                        try {
                            // If it decodes as base64url then assume binary
                            result.put(key, Base64url.decode(str));
                        } catch (IllegalArgumentException ex) {
                            result.put(key, str);
                        }
                    }
                    case ARRAY -> result.put(key, readRank1Array());
                    case OBJECT -> result.put(key, readRank1Map());
                    default -> throw new IOException("invalid type: " + reader.current());
                }
            }
            return result;
        } catch (JsonParserException e) {
            throw new IOException(e);
        }
    }

    @Override
    public void close() throws IOException {
        inputStream.close();
    }
}
