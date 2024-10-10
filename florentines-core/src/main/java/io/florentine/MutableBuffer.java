/*
 * Copyright 2024 Neil Madden.
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

import static java.util.Objects.checkIndex;
import static java.util.Objects.requireNonNull;

import java.util.Arrays;

/**
 * A simple byte buffer abstraction that can grow/shrink at the end.
 */
final class MutableBuffer {
    private byte[] bytes;
    private int length;

    private MutableBuffer(byte[] bytes, int length) {
        Require.between(length, 0, bytes.length+1, "length");
        this.bytes = requireNonNull(bytes);
        this.length = length;
    }

    static MutableBuffer of(byte[] bytes) {
        return new MutableBuffer(bytes.clone(), bytes.length);
    }

    static MutableBuffer of(byte[] bytes, int length) {
        return new MutableBuffer(bytes.clone(), length);
    }

    int capacity() {
        return bytes.length;
    }

    int length() {
        return length;
    }

    byte[] bytes() {
        return Arrays.copyOf(bytes, length);
    }

    private int remaining() {
        return capacity() - length();
    }

    MutableBuffer append(byte[] data) {
        if (remaining() < data.length) {
            int newCapacity = Math.max(2 * capacity(), capacity() + data.length);
            bytes = Arrays.copyOf(bytes, newCapacity);
        }
        System.arraycopy(data, 0, bytes, length, data.length);
        length += data.length;
        return this;
    }

    MutableBuffer append(int b) {
        return append(new byte[] { (byte) b });
    }

    MutableBuffer truncate(int newLength) {
        assert newLength <= length;
        length = newLength;
        return this;
    }

    byte get(int index) {
        return bytes[checkIndex(index, length)];
    }

    int getUnsigned(int index) {
        return get(index) & 0xFF;
    }

    @Override
    public String toString() {
        return "MutableBuffer{" +
                "bytes=" + Arrays.toString(bytes) +
                ", length=" + length +
                '}';
    }
}
