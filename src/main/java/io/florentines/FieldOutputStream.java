/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines;

import static io.florentines.Utils.require;
import static java.util.Objects.requireNonNull;

import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;
import java.io.OutputStream;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

final class FieldOutputStream implements Closeable, Flushable {
    private final OutputStream outputStream;
    private final CborEncoder encoder;

    FieldOutputStream(OutputStream outputStream) {
        this.encoder = new CborEncoder(requireNonNull(outputStream));
        this.outputStream = requireNonNull(outputStream);
    }

    void writeLength(int length) throws IOException {
        require(length >= 0 && length < 65536, "Length must fit in an unsigned short");
        encode(new UnsignedInteger(length));
    }

    void writeString(String value) throws IOException {
        encode(new UnicodeString(value));
    }

    void writeFixedLengthBytes(byte[] data) throws IOException {
        writeVariableLengthBytes(data);
    }

    void writeVariableLengthBytes(byte[] data) throws IOException {
        encode(new ByteString(data));
    }

    void writeByte(int b) throws IOException {
        encode(new UnsignedInteger(b & 0xFF));
    }

    @Override
    public void close() throws IOException {
        outputStream.close();
    }

    @Override
    public void flush() throws IOException {
        outputStream.flush();
    }

    private void encode(DataItem item) throws IOException {
        try {
            encoder.encode(item);
        } catch (CborException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new IOException(e);
        }
    }
}
