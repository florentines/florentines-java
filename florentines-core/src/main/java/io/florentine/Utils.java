/*
 * Copyright 2023 Neil Madden.
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

package io.florentine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;

public final class Utils {
    private static final Logger logger = LoggerFactory.getLogger(Utils.class);

    public static byte[] concat(byte[]... chunks) {
        // TODO: optimise this and provide specialisations for 2, 3, 4-arg cases to avoid varargs allocation
        var out = new ByteArrayOutputStream();
        for (var chunk : chunks) {
            out.writeBytes(chunk);
        }
        return out.toByteArray();
    }

    /**
     * Attempts to destroy the given key material. Any {@link DestroyFailedException}s thrown during the process are
     * ignored, because most Java built-in keys just throw the exception immediately without any attempt to wipe key
     * material from memory. The Salty Coffee library we use for crypto code does implement this correctly.
     *
     * @param toDestroy zero or more keys to destroy.
     */
    public static void destroy(Destroyable... toDestroy) {
        for (var it : toDestroy) {
            try {
                if (!it.isDestroyed()) {
                    it.destroy();
                }
            } catch (DestroyFailedException e) {
                // Ignore: the default behaviour of most Java built-in keys is to just throw DFE immediately.
                logger.debug("Failed to destroy key: {}", it, e);
            }
        }
    }

    public static void checkState(boolean condition, String msg) {
        if (!condition) {
            throw new IllegalStateException(msg);
        }
    }

    public static void rejectIf(boolean condition, String msg) {
        if (condition) {
            throw new IllegalArgumentException(msg);
        }
    }

    public static byte[] toUnsignedLittleEndian(BigInteger x, int expectedSize) {
        byte[] bytes = x.toByteArray();
        if (bytes.length > expectedSize && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        if (bytes.length > expectedSize) {
            throw new IllegalArgumentException("Value too big to represent in expected size");
        }
        reverseInPlace(bytes);
        if (bytes.length < expectedSize) {
            // Right-pad with zeroes
            bytes = Arrays.copyOf(bytes, expectedSize);
        }
        return bytes;
    }

    public static byte[] reverseInPlace(byte[] data) {
        int len = data.length;
        for (int i = 0; i < len >>> 1; ++i) {
            byte tmp = data[len - i - 1];
            data[len - i - 1] = data[i];
            data[i] = tmp;
        }
        return data;
    }

    public static void writeVarInt(OutputStream out, int length) throws IOException {
        rejectIf(length > Florentine.Packet.MAX_SIZE, "Value too large");
        rejectIf(length < 0, "Negative length");

        while (length > 0) {
            int b = length & 0x7F;
            if (length > 0x7F) {
                b |= 0x80;
            }
            out.write(b);
            length >>>= 7;
        }
    }

    public static int readVarInt(InputStream in) throws IOException {
        int value = 0, shift = 0, b;
        do {
            b = in.read();
            if (b == -1) { throw new EOFException(); }
            value += (b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0 && shift < 28);
        if (value > Florentine.Packet.MAX_SIZE || (b & 0x80) != 0) {
            throw new IOException("Varint too large");
        }
        return value;
    }

    public static String hexDump(byte[] data) {
        var sb = new StringBuilder();
        var line = new StringBuilder();
        for (int i = 0; i < data.length; ++i) {
            sb.append(String.format("%02x", data[i] & 0xFF));
            line.append(Character.isISOControl(data[i]) || Character.isWhitespace(data[i]) ? '.' : (char) data[i] );
            if (i % 8 == 7) {
                sb.append(" ");
            }
            if (i % 16 == 15) {
                sb.append(" ").append(line).append('\n');
                line.delete(0, line.length());
            }
        }

        int remaining = 16 - (data.length % 16);
        sb.append("  ".repeat(remaining));
        sb.append(" ".repeat((remaining / 8) + 1));
        sb.append(" ").append(line);

        return sb.toString();
    }

    /**
     * Returns the first element in the given collection, as determined by its iteration order. If the collection is
     * empty then it throws a {@link java.util.NoSuchElementException}.
     *
     * @param collection the collection. Must not be null.
     * @return the first element in the collection.
     * @param <T> the type of elements.
     * @throws java.util.NoSuchElementException if the collection is empty.
     * @throws NullPointerException if the collection is null.
     */
    public static <T> T first(Collection<T> collection) {
        return collection.iterator().next();
    }

    private Utils() {}
}
