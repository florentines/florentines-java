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

package io.florentine;

import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;

public class FlorentineTest {

    @Test
    public void testBasicOperation() {
        AlgorithmSuite alg = AlgorithmSuite.AUTHKEM_X25519_A256SIV_HS512;
        KeyPair alice = alg.generateKeyPair();
        KeyPair bob = alg.generateKeyPair();

        var florentine = Florentine.create(alg, alice, bob.getPublic())
                .contentType("fwt")
                .publicContent("This is a test - unencrypted")
                .secretContent("This is an encrypted test")
                .build();

        var copy = Florentine.fromString(florentine.toString()).orElseThrow();
        var contents = copy.decrypt(alg, bob, alice.getPublic());
        for (byte[] blob : contents) {
            System.out.println("Content: " + new String(blob));
        }
    }

    @Test
    public void testReadVarint() throws Exception {
        var in = new ByteArrayInputStream(new byte[] { (byte) 0x96, 0x01 });
        var val = Utils.readVarInt(in);
        assertThat(val).isEqualTo(150);
    }

    @Test(expectedExceptions = IOException.class)
    public void testReadVarintTooLarge() throws Exception {
        var in = new ByteArrayInputStream(new byte[] { -1, -1, -1, 1 });
        Utils.readVarInt(in);
    }

    @Test
    public void testWriteVarint() throws Exception {
        var out = new ByteArrayOutputStream();
        Utils.writeVarInt(out, 150);
        assertThat(out.toByteArray()).containsExactly(0x96, 0x01);
    }

    @Test
    public void testWriteVarint2() throws Exception {
        var out = new ByteArrayOutputStream();
        Utils.writeVarInt(out, Florentine.Packet.MAX_SIZE);
        assertThat(out.toByteArray()).containsExactly(0xFF, 0xFF, 0x7F);
    }

}