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

import com.grack.nanojson.JsonAppendableWriter;
import com.grack.nanojson.JsonWriter;
import io.florentine.Base64url;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.Objects;

public final class JsonDataWriter implements DataWriter {
    private final JsonAppendableWriter writer;
    private final OutputStream outputStream;

    public JsonDataWriter(OutputStream out) {
        this.outputStream = Objects.requireNonNull(out);
        this.writer = JsonWriter.on(outputStream);
    }

    @Override
    public void writeBool(boolean b) throws IOException {
        writer.value(b);
    }

    @Override
    public void writeInt(long i) {
        if (i < MIN_SAFE_INTEGER || i > MAX_SAFE_INTEGER) {
            throw new IllegalArgumentException("integer exceeds JSON-safe bounds");
        }
        writer.value(i);
    }

    @Override
    public void writeNum(double value) throws IOException {
        writeDouble(value);
    }

    @Override
    public void writeText(String s) throws IOException {
        writer.value(s);
    }

    @Override
    public void writeBytes(byte[] b) throws IOException {
        writer.value(Base64url.encode(b));
    }

    @Override
    public void writeRank1Array(Rank1Array array) throws IOException {
        writer.array();
        writeValues(array);
        writer.end();
    }

    @Override
    public void writeRank1Map(Rank1Map map) throws IOException {
        writer.object();
        writeMapValues(map);
        writer.end();
    }

    @Override
    public void writeRank2Array(Rank2Array array) throws IOException {
        writer.array();
        try {
            array.forEach(new Rank2ArrayVisitor<RuntimeException>() {
                @Override
                public void bool(boolean value) {
                    writer.value(value);
                }

                @Override
                public void integer(long i) {
                    writer.value(i);
                }

                @Override
                public void num(double value) {
                    writeDouble(value);
                }

                @Override
                public void text(String value) {
                    writer.value(value);
                }

                @Override
                public void bytes(byte[] value) {
                    writer.value(Base64url.encode(value));
                }

                @Override
                public void rank1Array(Rank1Array array) {
                    try {
                        writeRank1Array(array);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }

                @Override
                public void rank1Map(Rank1Map map) {
                    try {
                        writeRank1Map(map);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }
            });
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
        writer.end();

    }

    @Override
    public void writeRank2Map(Rank2Map map) throws IOException {
        writer.object();
        map.forEach(new Rank2MapVisitor<RuntimeException>() {
            @Override
            public void bool(String key, boolean value) {
                writer.value(key, value);
            }

            @Override
            public void integer(String key, long value) {
                writer.value(key, value);
            }

            @Override
            public void num(String key, double value) {
                writeDouble(key, value);
            }

            @Override
            public void text(String key, String value) {
                writer.value(key, value);
            }

            @Override
            public void bytes(String key, byte[] value) {
                writer.value(key, Base64url.encode(value));
            }

            @Override
            public void rank1Array(String key, Rank1Array array) {
                writer.array(key);
                writeValues(array);
                writer.end();
            }

            @Override
            public void rank1Map(String key, Rank1Map map) {
                writer.object(key);
                writeMapValues(map);
                writer.end();
            }
        });
        writer.end();
    }

    @Override
    public void close() throws IOException {
        writer.done();
        outputStream.close();
    }

    private void writeValues(Rank1Array array) {
        array.forEach(new Rank1ArrayVisitor<RuntimeException>() {
            @Override
            public void bool(boolean value) {
                writer.value(value);
            }

            @Override
            public void integer(long i) {
                writer.value(i);
            }

            @Override
            public void num(double value) {
                writeDouble(value);
            }

            @Override
            public void text(String value) {
                writer.value(value);
            }

            @Override
            public void bytes(byte[] value) {
                writer.value(Base64url.encode(value));
            }
        });
    }

    private void writeMapValues(Rank1Map map) {
        map.forEach(new Rank1MapVisitor<RuntimeException>() {
            @Override
            public void bool(String key, boolean value) {
                writer.value(key, value);
            }

            @Override
            public void integer(String key, long value) throws RuntimeException {
                writer.value(key, value);
            }

            @Override
            public void num(String key, double value) {
                writeDouble(key, value);
            }

            @Override
            public void text(String key, String value) {
                writer.value(key, value);
            }

            @Override
            public void bytes(String key, byte[] value) {
                writer.value(key, Base64url.encode(value));
            }
        });
    }

    private void writeDouble(double value) {
        if ((long) value == value) {
            // write as an integer if possible
            writer.value((long) value);
        } else {
            writer.value(value);
        }
    }

    private void writeDouble(String key, double value) {
        if ((long) value == value) {
            // write as an integer if possible
            writer.value(key, (long) value);
        } else {
            writer.value(key, value);
        }
    }
}
