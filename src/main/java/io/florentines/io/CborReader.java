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

package io.florentines.io;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Objects;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;

/**
 * Provides methods for reading structured data objects from an input stream in
 * <a href="https://cbor.io">CBOR</a>
 * format. Currently only partial support for the few data types used by Florentines is supported.
 */
public final class CborReader implements Closeable {
    private final InputStream inputStream;
    private final CborDecoder decoder;

    /**
     * Initializes the reader with the given input stream.
     *
     * @param inputStream the stream to read CBOR data items from.
     */
    public CborReader(InputStream inputStream) {
        this.inputStream = Objects.requireNonNull(inputStream, "inputStream");
        this.decoder = new CborDecoder(inputStream);
    }

    /**
     * Reads a variable-length byte array from the input stream.
     *
     * @return the read byte string.
     * @throws IOException if an I/O error occurs while reading the value or if the value read is not a byte string.
     */
    public byte[] readBytes() throws IOException {
        return decodeNext(ByteString.class).getBytes();
    }

    /**
     * Reads a fixed-length byte array from the input stream.
     *
     * @param expectedLength the expected length of the byte array.
     * @return the read byte string.
     * @throws IOException if an I/O error occurs while reading the value or if the value read is not a byte string
     * or if the read byte array is not of the expected size.
     * @implNote CBOR doesn't support fixed-size byte strings, so this uses {@link #readBytes()} and then checks the
     * length of the read array.
     */
    public byte[] readFixedLengthBytes(int expectedLength) throws IOException {
        var bytes = readBytes();
        if (bytes.length != expectedLength) {
            throw new IOException("Expected fixed-size byte array of length " + expectedLength + " but actual length "
                    + "read was " + bytes.length);
        }
        return bytes;
    }

    /**
     * Reads a Unicode string from the underlying input stream.
     *
     * @return the string that was read from the input.
     * @throws IOException if an I/O error occurs while reading the string or if the read data item is not a Unicode
     * string.
     */
    public String readString() throws IOException {
        return decodeNext(UnicodeString.class).getString();
    }

    /**
     * Begins reading a CBOR array from the input stream. The returned {@link ArrayReader} can be used to decode
     * the individual items in the array. Closing the returned stream ensures that all items in the array have been
     * processed.
     *
     * @return an {@link ArrayReader} to read individual items from the array.
     * @throws IOException if an I/O error occurs when reading the array.
     */
    public ArrayReader readArray() throws IOException {
        return new ArrayReader(decodeNext(Array.class));
    }

    /**
     * Closes the underlying input stream.
     *
     * @throws IOException if an I/O error occurs while closing the underlying stream.
     */
    @Override
    public void close() throws IOException {
        inputStream.close();
    }

    private <T extends DataItem> T decodeNext(Class<T> expectedType) throws IOException {
        try {
            var dataItem = decoder.decodeNext();
            if (expectedType.isInstance(dataItem)) {
                return expectedType.cast(dataItem);
            }
            throw new IOException("Unexpected CBOR data item - expected " + expectedType.getSimpleName() +
                    " but got " + dataItem.getClass().getSimpleName());
        } catch (CborException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new IOException(e);
        }
    }

    /**
     * A facade for reading data items from a CBOR array object.
     *
     * @implNote The current implementation reads the entire array contents into memory and then simply returns
     * subsequent items from the array data in response to method calls on this object.
     */
    public static final class ArrayReader implements Closeable {
        private final Iterator<DataItem> dataItemIterator;
        private final int size;

        private ArrayReader(Array items) {
            this.size = items.getDataItems().size();
            this.dataItemIterator = items.getDataItems().iterator();
        }

        /**
         * The total number of items in the array. This is not related to the number of bytes in the array, and the
         * value doesn't change as items are read from the array.
         *
         * @return the number of data items in the array.
         */
        public int size() {
            return size;
        }

        /**
         * Reads a variable-length byte array from the input stream.
         *
         * @return the read byte string.
         * @throws IOException if an I/O error occurs while reading the value or if the value read is not a byte string.
         */
        public byte[] readBytes() throws IOException {
            return readNext(ByteString.class).getBytes();
        }

        /**
         * Reads a fixed-length byte array from the input stream.
         *
         * @param expectedLength the expected length of the byte array.
         * @return the read byte string.
         * @throws IOException if an I/O error occurs while reading the value or if the value read is not a byte string
         * or if the read byte array is not of the expected size.
         * @implNote CBOR doesn't support fixed-size byte strings, so this uses {@link #readBytes()} and then checks the
         * length of the read array.
         */
        public byte[] readFixedLengthBytes(int expectedLength) throws IOException {
            var bytes = readBytes();
            if (bytes.length != expectedLength) {
                throw new IOException("Expected fixed-size byte array of length " + expectedLength +
                        " but actual length read was " + bytes.length);
            }
            return bytes;
        }

        /**
         * Reads a Unicode string from the underlying input stream.
         *
         * @return the string that was read from the input.
         * @throws IOException if an I/O error occurs while reading the string or if the read data item is not a Unicode
         * string.
         */
        public String readString() throws IOException {
            return readNext(UnicodeString.class).getString();
        }

        /**
         * Checks that all items have been consumed from the array by calling the various {@code readX()} methods.
         *
         * @throws IOException if not all elements of the array have been read.
         */
        @Override
        public void close() throws IOException {
            if (dataItemIterator.hasNext()) {
                throw new IOException("Extra items not read from array");
            }
        }

        private <T extends DataItem> T readNext(Class<T> expectedType) throws IOException {
            if (!dataItemIterator.hasNext()) {
                throw new EOFException();
            }
            var next = dataItemIterator.next();
            if (!expectedType.isInstance(next)) {
                throw new IOException("Unexpected CBOR data item in array: was expecting " +
                        expectedType.getSimpleName() + " but got " + next.getClass().getSimpleName());
            }
            return expectedType.cast(next);
        }
    }
}
