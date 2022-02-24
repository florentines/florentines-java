/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import org.testng.annotations.Test;

public class AesHmacSivDemTest {

    @Test
    public void test() {
        AesHmacSivDem dem = new AesHmacSivDem();
        DestroyableSecretKey key = dem.generateFreshKey();
        byte[][] packets = new byte[][] {
                "hello".getBytes(UTF_8),
                "world".getBytes(UTF_8)
        };
        byte[] siv = new byte[16];

        byte[] tag = dem.begin(key, siv).authenticate(packets[0]).encrypt(packets[1]);

        assertThat(packets[0]).asString(UTF_8).isEqualTo("hello");
        assertThat(packets[1]).asString(UTF_8).isNotEqualTo("world");

        byte[] computedTag = dem.begin(key, siv).authenticate(packets[0]).decrypt(packets[1]).orElseThrow();

        assertThat(packets[0]).asString(UTF_8).isEqualTo("hello");
        assertThat(packets[1]).asString(UTF_8).isEqualTo("world");
        assertThat(computedTag).isEqualTo(tag);
    }

}