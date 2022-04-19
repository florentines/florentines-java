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

public class XSalsa20HmacSivDemTest {

    @Test
    public void test() {
        var dem = new XSalsa20HmacSivDem();
        var key = dem.importKey(new byte[32]);
        byte[] plaintext = "Hello".getBytes(UTF_8);
        byte[] assocData = "World".getBytes(UTF_8);

        var sivAndCaveatKey =
                dem.beginEncryption(key).authenticate(assocData).encryptAndAuthenticate(plaintext).done();

        assertThat(assocData).asString(UTF_8).isEqualTo("World");
        assertThat(plaintext).asString(UTF_8).isNotEqualTo("Hello");

        var computedCaveatKey = dem.beginDecryption(key, sivAndCaveatKey.getFirst())
                .authenticate(assocData)
                .decryptAndAuthenticate(plaintext)
                .verify().orElseThrow();

        assertThat(plaintext).asString(UTF_8).isEqualTo("Hello");
        assertThat(assocData).asString(UTF_8).isEqualTo("World");
        assertThat(computedCaveatKey).isEqualTo(sivAndCaveatKey.getSecond());
    }

}