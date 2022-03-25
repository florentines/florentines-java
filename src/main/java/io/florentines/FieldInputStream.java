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
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;

final class FieldInputStream implements Closeable {
    private final InputStream inputStream;

    FieldInputStream(InputStream inputStream) {
        this.inputStream = requireNonNull(inputStream);
    }

    int readLength() throws IOException {
        var bytes = readNBytes(2);
        return ((bytes[1] & 0xFF) << 8) | (bytes[0] & 0xFF);
    }

    String readString() throws IOException {
        var length = readLength();
        var utf8 = ByteBuffer.wrap(readNBytes(length));
        var decoder = UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        return decoder.decode(utf8).toString();
    }

    byte[] readFixedLengthBytes(int length) throws IOException {
        require(length >= 0 && length < 65536, "Length must fit in an unsigned short");
        return readNBytes(length);
    }

    byte[] readVariableLengthBytes() throws IOException {
        var length = readLength();
        return readNBytes(length);
    }

    byte readByte() throws IOException {
        return readNBytes(1)[0];
    }

    private byte[] readNBytes(int size) throws IOException {
        byte[] read = inputStream.readNBytes(size);
        if (read.length != size) {
            throw new EOFException();
        }
        return read;
    }

    @Override
    public void close() throws IOException {
        inputStream.close();
    }
}
