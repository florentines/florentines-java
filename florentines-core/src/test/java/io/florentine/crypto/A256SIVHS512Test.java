/*
 * Copyright 2023 Neil Madden.
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

package io.florentine.crypto;

import org.testng.annotations.Test;

import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class A256SIVHS512Test {

    private static final SecretKey KEY = DEM.A256SIV_HS512.importKey(new byte[] {
             1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    });

    @Test
    public void testVector1() {
        var dem = DEM.A256SIV_HS512;
        var iv = new byte[] {
                -128, -127, -126, -125, -124, -123, -122, -121,
                -120, -119, -118, -117, -116, -115, -114, -113
        };
        var msg = "This is a test of the emergency broadcast system. Meet me at the café.";

        var msgBytes = msg.getBytes(UTF_8);
        var tag = dem.encrypt(KEY, msgBytes, iv);

        var decrypted = dem.decrypt(KEY, msgBytes, tag, iv).orElseThrow();
        assertThat(decrypted).asString(UTF_8).isEqualTo(msg);
    }

}