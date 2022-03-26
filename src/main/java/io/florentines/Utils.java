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

import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;

final class Utils {
    static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    static byte[] toUnsignedLittleEndian(BigInteger value, int length) {
        var bytes = value.toByteArray();
        if (bytes.length > length && bytes[0] == 0) {
            // Remove sign byte
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        reverse(bytes);
        if (bytes.length < length) {
            bytes = Arrays.copyOf(bytes, length);
        }
        return bytes;
    }

    static BigInteger fromUnsignedLittleEndian(byte[] littleEndian) {
        var bigEndian = littleEndian.clone();
        reverse(bigEndian);
        return new BigInteger(1, bigEndian);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    static void reverse(byte[] data) {
        byte tmp;
        for (int i = 0; i < (data.length >>> 1); ++i) {
            tmp = data[i];
            data[i] = data[data.length - i - 1];
            data[data.length - i - 1] = tmp;
        }
    }

    static String hex(byte[] data) {
        var i = new BigInteger(1, data);
        return String.format("%0" + (data.length << 1) + "x", i);
    }

    static boolean allZero(byte[] data) {
        byte sum = 0;
        for (byte datum : data) {
            sum |= datum;
        }
        return sum == 0;
    }

    /**
     * Attempts to wipe any sensitive data from memory by writing zero bytes over the array contents. This is a
     * best-effort attempt to remove data from memory, because Java's garbage collector may already have copied the
     * data in the heap.
     *
     * @param sensitiveData the sensitive data to wipe. Each non-null byte array argument is overwritten with zero
     *                      bytes. Null arguments are ignored.
     */
    static void wipe(byte[]... sensitiveData) {
        for (var data : sensitiveData) {
            if (data != null) {
                Arrays.fill(data, (byte) 0);
            }
        }
    }

    static <T extends DataItem> T readDataItem(CborDecoder decoder, Class<T> type) throws IOException {
        try {
            var dataItem = decoder.decodeNext();
            if (dataItem == null) {
                throw new EOFException();
            }
            if (type.isInstance(dataItem)) {
                return type.cast(dataItem);
            } else {
                throw new IOException("Unexpected CBOR data item: " + dataItem.getMajorType() +
                        " - expecting " + type.getSimpleName());
            }
        } catch (CborException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new IOException(e);
        }
    }
}
