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
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.assertj.core.api.SoftAssertions;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class CC20HS512Test {

    private DEM dem;
    private byte[] key;

    @BeforeMethod
    public void setup() {
        dem = new CC20HS512();
        key = new byte[32];
        for (int i = 0; i < 32; ++i) {
            key[i] = (byte) i;
        }
    }

    @Test
    public void shouldGenerateFreshKeys() {
        var key1 = dem.generateKey();
        var key2 = dem.generateKey();

        assertThat(key1).isNotEqualTo(key2);
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

        SoftAssertions.assertSoftly(softly -> {
            softly.assertThat(result).hasValue(tag);
            softly.assertThat(records.getFirst().secretContent().getFirst()).asString(UTF_8).isEqualTo("record a");
            softly.assertThat(records.getFirst().publicContent().getFirst()).asString(UTF_8).isEqualTo("assoc a");
            softly.assertThat(records.get(1).secretContent().getFirst()).asString(UTF_8).isEqualTo("record b");
            softly.assertThat(records.get(1).publicContent().getFirst()).asString(UTF_8).isEqualTo("assoc b");
        });
    }

    static final class TestRecord extends DEM.Record {
        private final byte[] secretContent;
        private final byte[] publicContent;
        private final byte[] assocData;

        TestRecord(byte[] secretContent, byte[] publicContent, byte[] assocData) {
            this.secretContent = secretContent;
            this.publicContent = publicContent;
            this.assocData = assocData;
        }

        @Override
        public List<byte[]> secretContent() {
            return List.of(secretContent);
        }

        @Override
        public List<byte[]> publicContent() {
            return List.of(assocData, publicContent);
        }
    }
}