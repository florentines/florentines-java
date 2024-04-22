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

import static org.assertj.core.api.Assertions.assertThat;

import org.testng.annotations.Test;

public class PaddingTest {

    @Test
    public void testPadme() {
        var padding = Padding.padme(10);
        for (int i = 0; i < 2000; ++i) {
            var paddedLen = padding.pad(new byte[i]);
            assertThat(paddedLen).isGreaterThanOrEqualTo(i);
            System.out.printf("%d -> %d%n", i, paddedLen);
            var padded = new byte[paddedLen + 1];
            padded[i] = (byte) 0x80;
//            System.out.printf("%2d -> %2d%n", i, padded.length);
            var unpadded = padding.unpad(padded);
            assertThat(unpadded).isEqualTo(i);
        }
    }
}