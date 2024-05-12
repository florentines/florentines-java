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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Random;

import org.testng.annotations.Test;

public class FlorentineTest {

    @Test
    public void testVarInts() throws Exception {
        var rand = new Random();
        var out = new ByteArrayOutputStream(9);
        for (int i = 0; i < 1000; ++i) {
            var l = rand.nextLong(65536);
            Florentine.writeVarInt(out, l);
            var l2 = Florentine.readVarInt(new ByteArrayInputStream(out.toByteArray()));
            out.reset();

            assertThat(l2).isEqualTo(l);
        }
    }
}