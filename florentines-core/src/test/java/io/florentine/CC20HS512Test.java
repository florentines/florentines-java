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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.List;

import org.assertj.core.api.SoftAssertions;
import org.testng.ITestResult;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class CC20HS512Test {

    private DEM dem = new CC20HS512();
    private byte[] key;
    private SoftAssertions softly;

    @BeforeMethod
    public void setup() {
        key = new byte[32];
        for (int i = 0; i < 32; ++i) {
            key[i] = (byte) i;
        }

        softly = new SoftAssertions();
    }

    @AfterMethod(alwaysRun = true)
    public void verifyAssertions(ITestResult result) {
        try {
            softly.assertAll();
        } catch (AssertionError e) {
            result.setStatus(ITestResult.FAILURE);
            result.setThrowable(e);
        }
    }

    @Test
    public void shouldRoundTrip() {
        // TODO: Split up test to check different things: does it encrypt? does it decyrpt? does it leave assoc data
        // unchanged? etc
        var records = List.of(
                new TestRecord("record a".getBytes(UTF_8), "public a".getBytes(UTF_8), "assoc a".getBytes(UTF_8)),
                new TestRecord("record b".getBytes(UTF_8), "public b".getBytes(UTF_8), "assoc b".getBytes(UTF_8)));

        var tag = dem.encapsulate(new DestroyableSecretKey(key, dem.identifier()), records);
        var result = dem.decapsulate(new DestroyableSecretKey(key, dem.identifier()), records, tag);

        softly.assertThat(result).hasValue(tag);
        softly.assertThat(records.getFirst().secretContent()).asString(UTF_8).isEqualTo("record a");
        softly.assertThat(records.getFirst().assocData()).asString(UTF_8).isEqualTo("assoc a");
        softly.assertThat(records.get(1).secretContent()).asString(UTF_8).isEqualTo("record b");
        softly.assertThat(records.get(1).assocData()).asString(UTF_8).isEqualTo("assoc b");
    }

    record TestRecord(byte[] secretContent, byte[] publicContent, byte[] assocData) implements DEM.Record {

    }
}