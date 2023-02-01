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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.pando.crypto.nacl.Crypto;

import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class X25519AnonKEMTest {

    private AnonKEM kem;

    @BeforeMethod
    public void setup() {
        kem = new X25519AnonKEM(DEM.A256SIV_HS512);
    }

    @Test
    public void testIdentifier() {
        assertThat(kem.getAlgorithmIdentifier()).isEqualTo("AnonKEM-X25519-A256SIV-HS512");
    }

    @Test
    public void testVector1() {
        var alice = kem.generateKeyPair();
        var bob = kem.generateKeyPair();

        var state = kem.beginEncap(List.of(bob.getPublic()), "Alice->Bob".getBytes(UTF_8));
        var demKey = state.key();
        var encap = state.encapsulate(Crypto.hash("foo".getBytes(UTF_8)));

        state = kem.beginDecap(bob, "Alice->Bob".getBytes(UTF_8));
        var demKey2 = state.decapsulate(Crypto.hash("foo".getBytes(UTF_8)), encap).orElseThrow();

        assertThat(demKey).isEqualTo(demKey2);
    }

}