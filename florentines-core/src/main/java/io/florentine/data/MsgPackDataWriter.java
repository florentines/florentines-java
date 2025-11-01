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

import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePacker;

import java.io.IOException;
import java.io.OutputStream;

public final class MsgPackDataWriter implements DataWriter {
    private final MessagePacker packer;

    public MsgPackDataWriter(OutputStream out) {
        this.packer = MessagePack.newDefaultPacker(out);
    }

    @Override
    public void writeBool(boolean b) throws IOException {
        packer.packBoolean(b);
    }

    @Override
    public void writeNum(double d) throws IOException {
        packer.packDouble(d);
    }

    @Override
    public void writeText(String s) throws IOException {
        packer.packString(s);
    }

    @Override
    public void writeBytes(byte[] b) throws IOException {
        packer.packBinaryHeader(b.length);
        packer.addPayload(b);
    }

    @Override
    public void writeRank1Array(Rank1Array array) throws IOException {
        packer.packArrayHeader(array.size());
        array.forEach(new Rank1ArrayVisitor<IOException>() {
            @Override
            public void bool(boolean value) throws IOException {
                packer.packBoolean(value);
            }

            @Override
            public void num(double value) throws IOException {
                packer.packDouble(value);
            }

            @Override
            public void text(String value) throws IOException {
                packer.packString(value);
            }

            @Override
            public void bytes(byte[] value) throws IOException {
                packer.packBinaryHeader(value.length);
                packer.addPayload(value);
            }
        });
    }

    @Override
    public void writeRank1Map(Rank1Map map) throws IOException {
        packer.packMapHeader(map.size());
        map.forEach(new Rank1MapVisitor<IOException>() {
            @Override
            public void bool(String key, boolean value) throws IOException {
                packer.packString(key);
                packer.packBoolean(value);
            }

            @Override
            public void num(String key, double value) throws IOException {
                packer.packString(key);
                packer.packDouble(value);
            }

            @Override
            public void text(String key, String value) throws IOException {
                packer.packString(key);
                packer.packString(value);
            }

            @Override
            public void bytes(String key, byte[] value) throws IOException {
                packer.packString(key);
                packer.packBinaryHeader(value.length);
                packer.addPayload(value);
            }
        });
    }

    @Override
    public void writeRank2Array(Rank2Array array) throws IOException {
        packer.packArrayHeader(array.size());
        array.forEach(new Rank2ArrayVisitor<IOException>() {
            @Override
            public void rank1Array(Rank1Array array) throws IOException {
                writeRank1Array(array);
            }

            @Override
            public void rank1Map(Rank1Map map) throws IOException {
                writeRank1Map(map);
            }

            @Override
            public void bool(boolean value) throws IOException {
                writeBool(value);
            }

            @Override
            public void num(double value) throws IOException {
                writeNum(value);
            }

            @Override
            public void text(String value) throws IOException {
                writeText(value);
            }

            @Override
            public void bytes(byte[] value) throws IOException {
                writeBytes(value);
            }
        });
    }

    @Override
    public void writeRank2Map(Rank2Map map) throws IOException {
        packer.packMapHeader(map.size());
        map.forEach(new Rank2MapVisitor<IOException>() {
            @Override
            public void rank1Array(String key, Rank1Array array) throws IOException {
                packer.packString(key);
                writeRank1Array(array);
            }

            @Override
            public void rank1Map(String key, Rank1Map map) throws IOException {
                packer.packString(key);
                writeRank1Map(map);
            }

            @Override
            public void bool(String key, boolean value) throws IOException {
                packer.packString(key);
                writeBool(value);
            }

            @Override
            public void num(String key, double value) throws IOException {
                packer.packString(key);
                writeNum(value);
            }

            @Override
            public void text(String key, String value) throws IOException {
                packer.packString(key);
                writeText(value);
            }

            @Override
            public void bytes(String key, byte[] value) throws IOException {
                packer.packString(key);
                writeBytes(value);
            }
        });
    }

    @Override
    public void close() throws IOException {
        packer.close();
    }
}
