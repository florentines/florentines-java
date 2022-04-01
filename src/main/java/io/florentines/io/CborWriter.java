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
import java.io.Flushable;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.DoublePrecisionFloat;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.SinglePrecisionFloat;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

/**
 *
 */
public final class CborWriter implements Closeable, Flushable {
    private final OutputStream outputStream;
    final CborEncoder encoder;

    public CborWriter(OutputStream outputStream) {
        this.outputStream = Objects.requireNonNull(outputStream, "outputStream");
        this.encoder = new CborEncoder(outputStream);
    }

    public CborWriter writeBytes(byte[] bytes) throws IOException {
        write(new ByteString(bytes));
        return this;
    }

    public CborWriter writeString(String string) throws IOException {
        write(new UnicodeString(string));
        return this;
    }

    public ArrayOutputStream beginArray() throws IOException {
        return new ArrayOutputStream(this);
    }

    public CborWriter writeObject(Object object) throws IOException {
        write(convert(object));
        return this;
    }

    @Override
    public void close() throws IOException {
        outputStream.close();
    }

    @Override
    public void flush() throws IOException {
        outputStream.flush();
    }

    private void write(DataItem dataItem) throws IOException {
        try {
            encoder.encode(dataItem);
        } catch (CborException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new IOException(e);
        }
    }

    private static DataItem convert(Object object) throws IOException {
        if (object == null) {
            return SimpleValue.NULL;
        } else if (object instanceof Boolean) {
            return ((boolean) object) ? SimpleValue.TRUE : SimpleValue.FALSE;
        } else if (object instanceof Byte || object instanceof Short || object instanceof Integer ||
                object instanceof Long) {
            long value = ((Number) object).longValue();
            return value < 0 ? new NegativeInteger(value) : new UnsignedInteger(value);
        } else if (object instanceof BigInteger) {
            var value = (BigInteger) object;
            return value.signum() >= 0 ? new UnsignedInteger(value) : new NegativeInteger(value);
        } else if (object instanceof Float) {
            return new SinglePrecisionFloat((float) object);
        } else if (object instanceof Double) {
            return new DoublePrecisionFloat((double) object);
        } else if (object instanceof byte[]) {
            return new ByteString((byte[]) object);
        } else if (object instanceof String) {
            return new UnicodeString((String) object);
        } else if (object instanceof List) {
            var list = (List<?>) object;
            var array = new Array(list.size());
            for (var item : list) {
                array.add(convert(item));
            }
            return array;
        } else if (object instanceof Map) {
            var map = (Map<?, ?>) object;
            var result = new co.nstant.in.cbor.model.Map();
            for (var entry : map.entrySet()) {
                result.put(convert(entry.getKey()), convert(entry.getValue()));
            }
            return result;
        } else {
            throw new IOException("Cannot convert object of class " + object.getClass() + " to CBOR");
        }
    }

    public static class ArrayOutputStream implements Closeable {
        private final ArrayBuilder<CborBuilder> builder;
        private final CborWriter cborWriter;

        private ArrayOutputStream(CborWriter cborWriter) {
            this.cborWriter = cborWriter;
            this.builder = new CborBuilder().addArray();
        }

        public ArrayOutputStream writeBytes(byte[] bytes) {
            builder.add(bytes);
            return this;
        }

        public ArrayOutputStream writeString(String string) {
            builder.add(string);
            return this;
        }

        public CborWriter end() throws IOException {
            try {
                cborWriter.encoder.encode(builder.end().build());
                return cborWriter;
            } catch (CborException e) {
                if (e.getCause() instanceof IOException) {
                    throw (IOException) e.getCause();
                }
                throw new IOException(e);
            }
        }

        @Override
        public void close() throws IOException {
            end();
        }
    }
}
