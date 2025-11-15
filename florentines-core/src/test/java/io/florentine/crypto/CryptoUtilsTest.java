/*
 * Copyright 2025 Neil Madden.
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

package io.florentine.crypto;

import org.testng.annotations.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class CryptoUtilsTest {

    @Test
    public void testAllZero() {
        var bytes = new byte[42];
        assertThat(CryptoUtils.allZero(bytes)).isTrue();
        bytes[3] ^= 1;
        assertThat(CryptoUtils.allZero(bytes)).isFalse();
        bytes[3] ^= 1;
        assertThat(CryptoUtils.allZero(bytes)).isTrue();
    }

    @Test
    public void testWipe() {
        // given
        var bytes = new byte[][] {
                { 0, 1, 2, 3, 4 },
                { -127, -126, -125 },
                {}
        };

        // when
        CryptoUtils.wipe(bytes);

        // then
        assertThat(bytes).isDeepEqualTo(new byte[][]{
                { 0, 0, 0, 0, 0 },
                { 0, 0, 0 },
                {}
        });
    }

    @Test
    public void testHashIsTruncatedSha512() {
        // given
        var message = "Well, hello there!";

        // when
        var hash = CryptoUtils.hash(message.getBytes(UTF_8));

        // then
        assertThat(hash).asHexString()
                .isEqualToIgnoringCase("cbc0c0f5c2350d1be58832ecc86e748790fd6b692c593a8f0d8b7b092c7a62db");
    }
}