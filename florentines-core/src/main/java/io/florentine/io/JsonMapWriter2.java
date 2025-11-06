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
import io.florentine.Base64url;
import io.florentine.data.Rank0DataVisitor;
import io.florentine.data.Rank0EntryVisitor;
import io.florentine.data.Rank1Array;
import io.florentine.data.Rank1EntryVisitor;
import io.florentine.data.Rank1Map;
import io.florentine.data.Rank2Map;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;

public final class JsonMapWriter2 implements MapWriter {
    private final OutputStream outputStream;
    private final JsonAppendableWriter jsonWriter;

    public JsonMapWriter2(OutputStream outputStream) {
        this.outputStream = outputStream;
        this.jsonWriter = JsonWriter.on(outputStream);
    }

    @Override
    public void writeMap(Rank2Map map) throws IOException {
        try {
            jsonWriter.object();
            map.forEach(Rank1EntryVisitor.visitor()
                    .onBoolean(jsonWriter::value)
                    .onLong(jsonWriter::value)
                    .onString(jsonWriter::value)
                    .onBytes(this::writeBytes)
                    .onArray(this::writeArray)
                    .onMap(this::writeMap));
            jsonWriter.end();
        } catch (UncheckedIOException e) {
            throw e.getCause();
        } catch (JsonWriterException e) {
            throw new IOException(e);
        }
    }

    @Override
    public void writeMap(Rank1Map map) throws IOException {
        try {
            jsonWriter.object();
            map.forEach(Rank0EntryVisitor.visitor()
                    .onBoolean(jsonWriter::value)
                    .onLong(jsonWriter::value)
                    .onString(jsonWriter::value)
                    .onBytes(this::writeBytes));
            jsonWriter.end();
        } catch (UncheckedIOException e) {
            throw e.getCause();
        } catch (JsonWriterException e) {
            throw new IOException(e);
        }
    }

    private void writeMap(String key, Rank1Map map) {
        try {
            jsonWriter.object(key);
            writeMap(map);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (JsonWriterException e) {
            throw new UncheckedIOException(new IOException(e));
        }
    }

    private void writeArray(String key, Rank1Array array) {
        try {
            jsonWriter.array(key);
            array.forEach(Rank0DataVisitor.visitor()
                    .onBoolean(jsonWriter::value)
                    .onLong(jsonWriter::value)
                    .onString(jsonWriter::value)
                    .onBytes(this::writeBytes));
        } catch (JsonWriterException e) {
            throw new UncheckedIOException(new IOException(e));
        }
    }

    private void writeBytes(String key, byte[] bytes) {
        jsonWriter.value(key, Base64url.encode(bytes));
    }

    private void writeBytes(byte[] bytes) {
        jsonWriter.value(Base64url.encode(bytes));
    }

    @Override
    public void close() throws IOException {
        try {
            jsonWriter.done();
        } catch (JsonWriterException e) {
            throw new IOException(e);
        } finally {
            outputStream.close();
        }
    }
}
