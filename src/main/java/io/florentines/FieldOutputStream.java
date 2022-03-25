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
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;
import java.io.OutputStream;

final class FieldOutputStream implements Closeable, Flushable {
    private final OutputStream outputStream;

    FieldOutputStream(OutputStream outputStream) {
        this.outputStream = requireNonNull(outputStream);
    }

    void writeLength(int length) throws IOException {
        require(length >= 0 && length < 65536, "Length must fit in an unsigned short");
        outputStream.write(length & 0xFF);
        outputStream.write((length >>> 8) & 0xFF);
    }

    void writeString(String value) throws IOException {
        byte[] utf8 = value.getBytes(UTF_8);
        writeVariableLengthBytes(utf8);
    }

    void writeFixedLengthBytes(byte[] data) throws IOException {
        outputStream.write(data);
    }

    void writeVariableLengthBytes(byte[] data) throws IOException {
        writeLength(data.length);
        outputStream.write(data);
    }

    void writeByte(int b) throws IOException {
        outputStream.write(b);
    }

    @Override
    public void close() throws IOException {
        outputStream.close();
    }

    @Override
    public void flush() throws IOException {
        outputStream.flush();
    }
}
