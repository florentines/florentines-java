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
    private static final byte[] KEY = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
            0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F
    };

    @Test
    public void test() {
        var dem = new XSalsa20HmacSivDem();
        var key = dem.importKey(KEY);
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