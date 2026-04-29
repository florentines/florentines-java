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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.List;

import static java.nio.charset.StandardCharsets.*;
import static org.assertj.core.api.Assertions.*;

public class DEMTest {

    @DataProvider
    public Object[][] supportedDEMs() {
        return new Object[][] {
                { "A128CTR-HS256" },
        };
    }

    @Test(dataProvider = "supportedDEMs")
    public void testRoundTrip(String demId) {
        // given
        var dem = DEM.get(demId).orElseThrow();
        var keyBytes = new byte[32];
        for (byte i = 0; i < 32; ++i) { keyBytes[i] = i; }
        var key = dem.importKey(keyBytes, 0);
        var msg = "This is a test of the emergency broadcast system".getBytes(UTF_8);

        // when
        var ciphertext = msg.clone();
        byte[] tag;
        try (var encapsulator = dem.beginEncapsulation(key.copy())) {
            tag = encapsulator.encapsulate(List.of(), List.of(ciphertext)).done();
        }
        var plaintext = ciphertext.clone();
        try (var decapsulator = dem.beginDecapsulation(key.copy(), tag)) {
            decapsulator.decapsulate(List.of(), List.of(plaintext));
        }

        assertThat(plaintext).isEqualTo(msg).isNotEqualTo(ciphertext);
    }
}