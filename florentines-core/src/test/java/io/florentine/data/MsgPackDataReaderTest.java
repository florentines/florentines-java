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

package io.florentine.data;

import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.util.HexFormat;

public class MsgPackDataReaderTest {

    @Test
    public void testIt() throws Exception {
        // given
        var data = (
                "83 a3 73 75 62 ac 74 65   73 74 20 73 75 62 6a 65 " +
                "63 74 a3 61 75 64 92 a3   66 6f 6f a3 62 61 72 a3 " +
                "65 78 70 ce 69 07 9c c2").replaceAll("\\s+", "");

        // when
        var reader = new MsgPackDataReader(new ByteArrayInputStream(HexFormat.of().parseHex(data)));
        var obj = reader.readRank2Map();

        // then
        System.out.println(obj);
    }
}