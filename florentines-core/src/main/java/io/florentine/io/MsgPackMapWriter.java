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

package io.florentine.io;

import io.florentine.data.Rank1Array;
import io.florentine.data.Rank1DataVisitor;
import io.florentine.data.Rank1EntryVisitor;
import io.florentine.data.Rank1Map;
import io.florentine.data.Rank2Map;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePacker;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;

public final class MsgPackMapWriter implements MapWriter, Rank1EntryVisitor, Rank1DataVisitor {
    private final MessagePacker messagePacker;

    public MsgPackMapWriter(OutputStream out) {
        this.messagePacker = MessagePack.newDefaultPacker(out);
    }

    @Override
    public void boolValue(boolean value) {
        try {
            messagePacker.packBoolean(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void longValue(long value) {
        try {
            messagePacker.packLong(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void textValue(String value) {
        try {
            messagePacker.packString(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void byteValue(byte[] value) {
        try {
            messagePacker.packBinaryHeader(value.length);
            messagePacker.addPayload(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void rank1Array(String key, Rank1Array array) {
        try {
            messagePacker.packString(key);
            array.forEach(this);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void rank1Map(String key, Rank1Map map) {
        try {
            messagePacker.packString(key);
            map.forEach(this);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void boolValue(String key, boolean value) {
        try {
            messagePacker.packString(key);
            messagePacker.packBoolean(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void longValue(String key, long value) {
        try {
            messagePacker.packString(key);
            messagePacker.packLong(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void textValue(String key, String value) {
        try {
            messagePacker.packString(key);
            messagePacker.packString(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void byteValue(String key, byte[] value) {
        try {
            messagePacker.packString(key);
            messagePacker.packBinaryHeader(value.length);
            messagePacker.addPayload(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void rank1Array(Rank1Array array) {
        try {
            messagePacker.packArrayHeader(array.size());
            array.forEach(this);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void rank1Map(Rank1Map map) {
        try {
            messagePacker.packMapHeader(map.size());
            map.forEach(this);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void writeMap(Rank2Map map) throws IOException {
        messagePacker.packMapHeader(map.size());
        try {
            map.forEach(this);
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    @Override
    public void writeMap(Rank1Map map) throws IOException {
        try {
            rank1Map(map);
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    @Override
    public void close() throws IOException {
        messagePacker.close();
    }
}
