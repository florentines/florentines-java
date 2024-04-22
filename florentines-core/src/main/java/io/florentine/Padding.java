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

public abstract class Padding {
    /**
     * Determines how much padding to apply to the unpadded input.
     *
     * @param unpadded the unpadded input.
     * @return the length to pad the input to. This should be >= the unpadded length.
     */
    abstract int pad(byte[] unpadded);

    /**
     * Determines how much padding to remove.
     *
     * @param padded the padded data.
     * @return the length of the data up to the start of the padding.
     */
    abstract int unpad(byte[] padded);

    static Padding none() {
        return new Padding() {
            @Override
            int pad(byte[] unpadded) {
                return unpadded.length;
            }

            @Override
            int unpad(byte[] padded) {
                return padded.length;
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
        return new Padding() {
            @Override
            int pad(byte[] unpadded) {
                int paddedLength;
                if (unpadded.length < minLength) {
                    paddedLength = minLength;
                } else {
                    var e = log2(unpadded.length);
                    var s = log2(e) + 1;
                    var lastBits = e - s;
                    var bitMask = (1 << lastBits) - 1;
                    paddedLength = (unpadded.length + bitMask) & ~bitMask;
                }
                return paddedLength;
            }

            @Override
            int unpad(byte[] padded) {
                // Padmé guarantees the padding is never more than 12% more than the original size
                var maxPadLength = padded.length < Math.max(minLength, 512)
                        ? padded.length : (int)(padded.length * 0.12d) + 1;
                byte acc = 0;
                int padLen = 0;
                byte valid = 0;
                // We try to determine the length of the padding in constant time.
                for (int i = 0; i < maxPadLength; ++i) {
                    byte c = padded[padded.length - i - 1];
                    int end = ((((acc & 0xFF) - 1) & (padLen - 1) & (((c & 0xFF) ^ 0x80) - 1)) >>> 8) & 1;
                    acc |= c;
                    padLen |= i & (1 + ~end);
                    valid |= (byte) end;
                }
                if (valid == 0) {
                    throw new IllegalArgumentException("invalid padding");
                }
                return padded.length - padLen - 1;
            }

            int log2(double x) {
                return (int) Math.floor(Math.log(x) * log2);
            }
        };
    }
}
