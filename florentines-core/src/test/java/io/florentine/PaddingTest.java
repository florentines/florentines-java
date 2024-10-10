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

import static org.assertj.core.api.SoftAssertions.assertSoftly;

import java.util.Random;

import org.assertj.core.api.Assertions;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class PaddingTest {

    @Test
    public void shouldRoundTripValidPadding() {
        assertSoftly(softly -> {
            for (int i = 0; i < 100; ++i) {
                var data = MutableBuffer.of(new byte[200], 0);
                for (int j = 0; j < i; ++j) {
                    data.append(42);
                }

                var padded = Padding.pad(data, 150);
                var unpadded = Padding.unpad(padded, 0).orElseThrow();
                softly.assertThat(unpadded.length()).isEqualTo(i);
            }
        });
    }

    @Test
    public void shouldRejectInvalidPadding() {
        assertSoftly(softly -> {
            for (int i = 0; i < 256; ++i) {
                if (i == 0x80) continue;
                var data = MutableBuffer.of(new byte[1], 0);
                data.append(i);
                softly.assertThat(Padding.unpad(data, 0)).isEmpty();
            }
        });
    }

    @Test
    public void shouldRejectRandomGarbage() {
        var rand = new Random();
        var random = new byte[100];
        assertSoftly(softly -> {
            for (int i = 0; i < 1000; ++i) {
                rand.nextBytes(random);
                avoidAccidentallyCorrectPadding(random);
                softly.assertThat(Padding.unpad(MutableBuffer.of(random), 0)).isEmpty();
            }
        });
    }

    private void avoidAccidentallyCorrectPadding(byte[] data) {
        for (var i = data.length-1; i >= 0; --i) {
            if (data[i] == 0) continue;
            if (data[i] == (byte) 0x80) {
                data[i] = 42;
            }
            break;
        }
    }

    @DataProvider
    public Object[][] padmeTestCases() {
        return new Object[][] {
                {0, 0},
                {1, 1},
                {2, 2},
                {3, 3},
                {4, 4},
                {5, 5},
                {6, 6},
                {7, 7},
                {8, 8},
                {9, 10},
                {10, 10},
                {11, 12},
                {12, 12},
                {13, 14},
                {14, 14},
                {15, 16},
                {16, 16},
                {17, 18},
                {18, 18},
                {19, 20},
                {20, 20},
                {21, 22},
                {22, 22},
                {23, 24},
                {24, 24},
                {25, 26},
                {26, 26},
                {27, 28},
                {28, 28},
                {29, 30},
                {30, 30},
                {31, 32},
                {32, 32},
                {33, 36},
                {34, 36},
                {35, 36},
                {36, 36},
                {37, 40},
                {38, 40},
                {39, 40},
                {40, 40},
                {41, 44},
                {42, 44},
                {43, 44},
                {44, 44},
                {45, 48},
                {46, 48},
                {47, 48},
                {48, 48},
                {49, 52},
                {50, 52},
                {51, 52},
                {52, 52},
                {53, 56},
                {54, 56},
                {55, 56},
                {56, 56},
                {57, 60},
                {58, 60},
                {59, 60},
                {60, 60},
                {61, 64},
                {62, 64},
                {63, 64},
                {64, 64},
                {65, 72},
                {66, 72},
                {67, 72},
                {68, 72},
                {69, 72},
                {70, 72},
                {71, 72},
                {72, 72},
                {73, 80},
                {74, 80},
                {75, 80},
                {76, 80},
                {77, 80},
                {78, 80},
                {79, 80},
                {80, 80},
                {81, 88},
                {82, 88},
                {83, 88},
                {84, 88},
                {85, 88},
                {86, 88},
                {87, 88},
                {88, 88},
                {89, 96},
                {90, 96},
                {91, 96},
                {92, 96},
                {93, 96},
                {94, 96},
                {95, 96},
                {96, 96},
                {97, 104},
                {98, 104},
                {99, 104},
                {100, 104},
        };
    }

    @Test(dataProvider = "padmeTestCases")
    public void shouldMatchPadmeExpectedValues(int unpaddedLen, int paddedLen) {
        Assertions.assertThat(Padding.padme(unpaddedLen, 0)).isEqualTo(paddedLen);
    }
}