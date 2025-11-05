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

import com.grack.nanojson.JsonAppendableWriter;
import com.grack.nanojson.JsonWriter;
import com.grack.nanojson.JsonWriterException;
import io.florentine.data.Rank1Array;
import io.florentine.data.Rank1DataVisitor;
import io.florentine.data.Rank1EntryVisitor;
import io.florentine.data.Rank1Map;
import io.florentine.data.Rank2Map;

import java.io.IOException;
import java.io.OutputStream;

import static java.util.Objects.requireNonNull;

public final class JsonMapWriter implements MapWriter, Rank1EntryVisitor, Rank1DataVisitor {
    private final OutputStream outputStream;
    private final JsonAppendableWriter jsonWriter;

    public JsonMapWriter(OutputStream out) {
        this.outputStream = requireNonNull(out);
        this.jsonWriter = JsonWriter.on(out);
    }

    @Override
    public void writeMap(Rank2Map map) throws IOException {
        try {
            jsonWriter.object();
            map.forEach(this);
            jsonWriter.end();
        } catch (JsonWriterException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new IOException(e);
        }
    }

    @Override
    public void writeMap(Rank1Map map) throws IOException {
        try {
            rank1Map(map);
        } catch (JsonWriterException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new IOException(e);
        }
    }

    @Override
    public void close() throws IOException {
        outputStream.close();
    }

    @Override
    public void rank1Array(String key, Rank1Array array) {
        jsonWriter.array(key);
        array.forEach(this);
        jsonWriter.end();
    }

    @Override
    public void rank1Map(String key, Rank1Map map) {
        jsonWriter.object(key);
        map.forEach(this);
        jsonWriter.end();
    }

    @Override
    public void boolValue(String key, boolean value) {
        jsonWriter.value(key, value);
    }

    @Override
    public void longValue(String key, long value) {
        jsonWriter.value(key, value);
    }

    @Override
    public void textValue(String key, String value) {
        jsonWriter.value(key, value);
    }

    @Override
    public void byteValue(String key, byte[] value) {
        jsonWriter.value(key, value);
    }

    @Override
    public void rank1Array(Rank1Array array) {
        jsonWriter.array();
        array.forEach(this);
        jsonWriter.end();
    }

    @Override
    public void rank1Map(Rank1Map map) {
        jsonWriter.object();
        map.forEach(this);
        jsonWriter.end();
    }

    @Override
    public void boolValue(boolean value) {
        jsonWriter.value(value);
    }

    @Override
    public void longValue(long value) {
        jsonWriter.value(value);
    }

    @Override
    public void textValue(String value) {
        jsonWriter.value(value);
    }

    @Override
    public void byteValue(byte[] value) {
        jsonWriter.value(value);
    }
}
