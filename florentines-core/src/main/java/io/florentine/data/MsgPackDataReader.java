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
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;
import java.io.InputStream;

public final class MsgPackDataReader implements DataReader {
    private final MessageUnpacker unpacker;

    public MsgPackDataReader(InputStream in) {
        this.unpacker = MessagePack.newDefaultUnpacker(in);
    }

    @Override
    public boolean readBool() throws IOException {
        return unpacker.unpackBoolean();
    }

    @Override
    public long readInt() throws IOException {
        return unpacker.unpackLong();
    }

    @Override
    public double readNum() throws IOException {
        return unpacker.unpackDouble();
    }

    @Override
    public String readText() throws IOException {
        return unpacker.unpackString();
    }

    @Override
    public byte[] readBytes() throws IOException {
        int size = unpacker.unpackBinaryHeader();
        return unpacker.readPayload(size);
    }

    @Override
    public Rank1Array readRank1Array() throws IOException {
        int numItems = unpacker.unpackArrayHeader();
        var result = Rank1Array.of();
        while (numItems-- > 0) {
            switch (unpacker.getNextFormat().getValueType()) {
                case INTEGER -> result.add(unpacker.unpackLong());
                case FLOAT -> result.add(unpacker.unpackDouble());
                case BOOLEAN -> result.add(unpacker.unpackBoolean());
                case STRING -> result.add(unpacker.unpackString());
                case BINARY -> result.add(readBytes());
                default -> throw new IOException("Unexpected type: " + unpacker.getNextFormat());
            }
        }
        return result;
    }

    @Override
    public Rank1Map readRank1Map() throws IOException {
        int numEntries = unpacker.unpackMapHeader();
        var result = new Rank1Map();
        while (numEntries-- > 0) {
            var key = unpacker.unpackString();
            switch (unpacker.getNextFormat().getValueType()) {
                case INTEGER -> result.put(key, unpacker.unpackLong());
                case FLOAT -> result.put(key, unpacker.unpackDouble());
                case BOOLEAN -> result.put(key, unpacker.unpackBoolean());
                case STRING -> result.put(key, unpacker.unpackString());
                case BINARY -> result.put(key, readBytes());
                default -> throw new IOException("Unexpected type: " + unpacker.getNextFormat());
            }
        }
        return result;
    }

    @Override
    public Rank2Array readRank2Array() throws IOException {
        int numItems = unpacker.unpackArrayHeader();
        var result = Rank2Array.of();
        while (numItems-- > 0) {
            switch (unpacker.getNextFormat().getValueType()) {
                case INTEGER -> result.add(unpacker.unpackLong());
                case FLOAT -> result.add(unpacker.unpackDouble());
                case BOOLEAN -> result.add(unpacker.unpackBoolean());
                case STRING -> result.add(unpacker.unpackString());
                case BINARY -> result.add(readBytes());
                case ARRAY -> result.add(readRank1Array());
                case MAP -> result.add(readRank1Map());
                default -> throw new IOException("Unexpected type: " + unpacker.getNextFormat());
            }
        }
        return result;
    }

    @Override
    public Rank2Map readRank2Map() throws IOException {
        int numEntries = unpacker.unpackMapHeader();
        var result = new Rank2Map();
        while (numEntries-- > 0) {
            var key = unpacker.unpackString();
            switch (unpacker.getNextFormat().getValueType()) {
                case INTEGER -> result.put(key, unpacker.unpackLong());
                case FLOAT -> result.put(key, unpacker.unpackDouble());
                case BOOLEAN -> result.put(key, unpacker.unpackBoolean());
                case STRING -> result.put(key, unpacker.unpackString());
                case BINARY -> result.put(key, readBytes());
                case ARRAY -> result.put(key, readRank1Array());
                case MAP -> result.put(key, readRank1Map());
                default -> throw new IOException("Unexpected type: " + unpacker.getNextFormat());
            }
        }
        return result;
    }

    @Override
    public void close() throws IOException {
        unpacker.close();
    }
}
