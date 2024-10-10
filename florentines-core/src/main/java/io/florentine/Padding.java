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

import java.util.Optional;

final class Padding {

    static MutableBuffer pad(MutableBuffer unpadded, int newLength) {
        assert newLength >= unpadded.length();
        unpadded.append(0x80);
        unpadded.append(new byte[Math.max(newLength - unpadded.length(), 0)]);
        return unpadded;
    }

    static Optional<MutableBuffer> unpad(MutableBuffer padded, int minUnpaddedLength) {
        assert minUnpaddedLength >= 0;
        // Constant-time unpadding implementation adapted from libsodium
        int seenNonZero = 0; // Becomes non-zero at first encounter of a non-zero byte
        int padLen = 0;
        int valid = 0;

        var paddedLen = padded.length();
        for (int i = paddedLen-1; i >= minUnpaddedLength; --i) {
            int c = padded.getUnsigned(i);
            int isBarrier = (((seenNonZero - 1) & (padLen - 1) & ((c ^ 0x80) - 1)) >>> 8) & 1;
            seenNonZero |= c;
            padLen |= (paddedLen - i) & (1 + ~isBarrier);
            valid |= isBarrier;
        }
        return valid - 1 != 0 ? Optional.empty() : Optional.of(padded.truncate(paddedLen - padLen));
    }

    static int padme(int unpaddedLength, int minLength) {
        assert minLength >= 0;
        if (unpaddedLength < minLength) {
            return minLength;
        }
        if (unpaddedLength < 2) {
            // The formulas below don't work for 0 or 1 values
            return unpaddedLength;
        }
        var e = (int) Math.floor(log2(unpaddedLength));
        var s = (int) Math.floor(log2(e)) + 1;
        var mask = (1 << (e - s)) - 1;
        return (unpaddedLength + mask) & ~mask;
    }

    private static final double ONE_OVER_LOG2 = 1.0d / Math.log(2d);

    static double log2(double x) {
        return Math.log(x) * ONE_OVER_LOG2;
    }

}
