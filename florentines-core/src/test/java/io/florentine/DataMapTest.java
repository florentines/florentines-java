/*
 * Copyright 2026 Neil Madden.
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

import org.testng.annotations.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class DataMapTest {

    @Test
    public void shouldRoundTripToBinaryFormat() {
        // Given
        var map = DataMap.builder()
                .put("bool", true)
                .put("long", Long.MAX_VALUE)
                .put("string", "Hello, World!")
                .put("binary", new byte[] { 0, 1, 2, 3, 4})
                .put("array", List.of("a", "b", "c"))
                .put("map", Map.of("a", "1", "b", "2"))
                .build();

        // When
        var bytes = DataMapUtils.toBytes(map);
        var result = DataMapUtils.fromBytes(bytes);

        // Then
        assertThat(result).contains(map);
    }
}