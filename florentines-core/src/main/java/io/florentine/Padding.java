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

import java.util.Arrays;

public abstract class Padding {

    private final int minPadLength;

    private Padding(int minPadLength) {
        this.minPadLength = minPadLength;
    }

    /**
     * Determines how much padding to apply to the unpadded input.
     *
     * @param unpadded the unpadded input.
     * @return the length to pad the input to. This should be >= the unpadded length.
     */
    public PaddedBytes pad(byte[] unpadded, int unpaddedLength) {
        int paddedLength = paddedLength(unpaddedLength) + 1; // Always add a single 0x80 byte
        byte[] padded = unpadded;
        if (paddedLength > unpadded.length) {
            padded = Arrays.copyOf(unpadded, paddedLength);
            CryptoUtils.wipe(unpadded);
        }
        padded[unpaddedLength] = (byte) 0x80;
        Arrays.fill(padded, unpaddedLength + 1, padded.length, (byte) 0);
        return new PaddedBytes(padded, paddedLength);
    }

    public record PaddedBytes(byte[] bytes, int length) {}

    abstract int paddedLength(int unpaddedLength);

    /**
     * Determines how much padding to remove.
     *
     * @param padded the padded data.
     * @return the length of the data up to the start of the padding.
     */
    public int unpad(byte[] padded, int paddedLength) {
        // Padmé guarantees the padding is never more than 12% more than the original size
        var maxPadLength = paddedLength < minPadLength ? paddedLength : (int)(paddedLength * 0.12d) + 1;
        byte acc = 0;
        int padLen = 0;
        byte valid = 0;
        // We try to determine the length of the padding in constant time.
        for (int i = 0; i < maxPadLength; ++i) {
            byte c = padded[paddedLength - i - 1];
            int end = ((((acc & 0xFF) - 1) & (padLen - 1) & (((c & 0xFF) ^ 0x80) - 1)) >>> 8) & 1;
            acc |= c;
            padLen |= i & (1 + ~end);
            valid |= (byte) end;
        }
        if (valid == 0) {
            throw new IllegalArgumentException("invalid padding");
        }
        return paddedLength - padLen - 1;

    }

    static Padding none() {
        return new Padding(0) {
            @Override
            int paddedLength(int unpaddedLength) {
                return unpaddedLength;
            }
        };
    }

    /*
     * Sketch of new approach to padding:
     * Make each record have a byte[] array and a length field. The length field can be less than the array length (eg
     * after compression or padding is removed) or it may be *more* than the array length. This latter case indicates
     * that padding should be applied when the record is written to output.
     */

    static Padding padme(final int minLength) {
        final double log2 = 1.0d / Math.log(2.0d);
        return new Padding(minLength) {
            @Override
            int paddedLength(int unpaddedLength) {
                int paddedLength;
                if (unpaddedLength < minLength) {
                    paddedLength = minLength;
                } else {
                    var e = log2(unpaddedLength);
                    var s = log2(e) + 1;
                    var lastBits = e - s;
                    var bitMask = (1 << lastBits) - 1;
                    paddedLength = (unpaddedLength + bitMask) & ~bitMask;
                }
                return paddedLength;
            }

            int log2(double x) {
                return (int) Math.floor(Math.log(x) * log2);
            }
        };
    }
}
