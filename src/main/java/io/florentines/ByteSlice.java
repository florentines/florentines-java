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

import static java.util.Objects.checkFromIndexSize;
import static java.util.Objects.requireNonNull;

import java.nio.ByteBuffer;

public final class ByteSlice {
    final byte[] buffer;
    final int offset;
    final int length;

    public ByteSlice(byte[] buffer, int offset, int length) {
        this.buffer = requireNonNull(buffer);
        this.offset = checkFromIndexSize(offset, length, buffer.length);
        this.length = length;
    }

    public static ByteSlice of(byte[] data, int offset, int length) {
        return new ByteSlice(data, offset, length);
    }

    public static ByteSlice of(byte[] data) {
        return of(data, 0, data.length);
    }

    public ByteSlice truncate(int newLength) {
        return of(buffer, offset, checkFromIndexSize(offset, newLength, buffer.length));
    }

    public ByteSlice subSlice(int offset, int newLength) {
        if (newLength > length - offset) {
            throw new ArrayIndexOutOfBoundsException("New length is out of bounds of current slice");
        }
        checkFromIndexSize(this.offset + offset, newLength, buffer.length);
        return new ByteSlice(buffer, this.offset + offset, newLength);
    }

    public ByteBuffer toByteBuffer() {
        return ByteBuffer.wrap(buffer, offset, length).asReadOnlyBuffer();
    }
}
