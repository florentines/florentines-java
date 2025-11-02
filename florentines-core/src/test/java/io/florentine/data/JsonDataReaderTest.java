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

import static java.nio.charset.StandardCharsets.UTF_8;

public class JsonDataReaderTest {


    @Test
    public void testIt() throws Exception {
        // given
        var json = """
                {"sub":"test subject","aud":["foo","bar"],"exp":1762094121}
                """;

        // when
        var reader = new JsonDataReader(new ByteArrayInputStream(json.getBytes(UTF_8)));
        var obj = reader.readRank2Map();

        // then
        System.out.println(obj);
    }
}