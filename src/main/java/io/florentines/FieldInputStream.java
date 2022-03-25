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
import java.io.IOException;
import java.io.InputStream;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

final class FieldInputStream implements Closeable {
    private final InputStream inputStream;
    private final CborDecoder decoder;

    FieldInputStream(InputStream inputStream) {
        this.inputStream = requireNonNull(inputStream);
        this.decoder = new CborDecoder(inputStream);
    }

    int readLength() throws IOException {
        return decodeNext(UnsignedInteger.class).getValue().intValueExact();
    }

    String readString() throws IOException {
        return decodeNext(UnicodeString.class).getString();
    }

    byte[] readFixedLengthBytes(int length) throws IOException {
        require(length >= 0 && length < 65536, "Length must fit in an unsigned short");
        var bytes = readVariableLengthBytes();
        if (bytes.length != length) {
            throw new IOException("Byte string not of expected length");
        }
        return bytes;
    }

    byte[] readVariableLengthBytes() throws IOException {
        return decodeNext(ByteString.class).getBytes();
    }

    byte readByte() throws IOException {
        return decodeNext(UnsignedInteger.class).getValue().byteValueExact();
    }

    @Override
    public void close() throws IOException {
        inputStream.close();
    }

    private <T extends DataItem> T decodeNext(Class<T> expectedType) throws IOException {
        try {
            var dataItem = decoder.decodeNext();
            if (expectedType.isInstance(dataItem)) {
                return expectedType.cast(dataItem);
            } else {
                throw new IOException("Unexpected CBOR data item: " + dataItem.getMajorType());
            }
        } catch (CborException e) {
            throw new IOException(e);
        }
    }
}
