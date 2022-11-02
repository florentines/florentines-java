/*
 * Copyright 2022 Neil Madden.
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

package software.pando.florentines;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.util.Base64;
import java.util.List;

import org.testng.annotations.Test;

public class X25519AuthKemTest {

    @Test
    public void testBasicOperation() {
        KEM kem = Algorithm.AUTHKEM_X25519_XS20SIV_HS256.kem;
        KeyPair senderKeys = kem.generateKeyPair();
        KeyPair recipientKeys = kem.generateKeyPair();

        KeyInfo sender = new KeyInfo(senderKeys.getPrivate(), senderKeys.getPublic(),
                Algorithm.AUTHKEM_X25519_XS20SIV_HS256, "Alice");
        KeyInfo recipient = new KeyInfo(recipientKeys.getPrivate(), recipientKeys.getPublic(),
                Algorithm.AUTHKEM_X25519_XS20SIV_HS256, "Bob");

        var encapKey = kem.encapsulate(sender, List.of(recipient), "Hello".getBytes());
        System.out.println("Encapsulated key: " + Base64.getUrlEncoder().encodeToString(encapKey.encapsulation));
        System.out.println("Length (raw): " + encapKey.encapsulation.length + ", (b64): " + Base64.getUrlEncoder().encodeToString(encapKey.encapsulation).length());
        var decapKey = kem.decapsulate(List.of(recipient), List.of(sender), encapKey.encapsulation, "Hello".getBytes());

        assertThat(decapKey).isPresent();
        assertThat(decapKey.get().key).isEqualTo(encapKey.key);
    }

}