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

    @Test
    public void testApi() throws Exception {
        var alice = CryptoSuite.X25519_CC20_HS512.newKeySetFor("test", "Alice".getBytes(UTF_8));
        var bob = CryptoSuite.X25519_CC20_HS512.newKeySetFor("test", "Bob".getBytes(UTF_8));

        var florentine = Florentine.createFrom(alice)
                .to(bob.toPublicKeySet())
                .paddingMethod(Padding.padme(32))
                .contentType("json")
                .secretPayload("""
                        {"Hello": "World!"}
                        """.getBytes(UTF_8))
                .build();

        System.out.println("Florentine: " + florentine);
        System.out.println("Length: " + florentine.toString().length());
    }
}