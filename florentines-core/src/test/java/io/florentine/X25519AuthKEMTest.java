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

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class X25519AuthKEMTest {

    private KeyPair aliceKeys;
    private KeyPair bobKeys;

    private X25519AuthKEM kem = new X25519AuthKEM(CryptoSuite.X25519_CC20_HS512);

    @BeforeClass
    public void generateKeys() throws Exception {
        aliceKeys = kem.generateKeyPair();
        bobKeys = kem.generateKeyPair();
    }

    @Test(expectedExceptions = { NullPointerException.class, IllegalArgumentException.class })
    public void shouldRejectNullKeyPair() {
        kem.validateKeyPair(null);
    }

    @Test(expectedExceptions = { NullPointerException.class, IllegalArgumentException.class })
    public void shouldRejectNullPrivateKey() {
        kem.validateKeyPair(new KeyPair(aliceKeys.getPublic(), null));
    }

    @Test(expectedExceptions = { NullPointerException.class, IllegalArgumentException.class })
    public void shouldRejectNullPublicKey() {
        kem.validateKeyPair(new KeyPair(null, aliceKeys.getPrivate()));
    }

    @Test(expectedExceptions = { IllegalArgumentException.class })
    public void shouldRejectNonX25519Keys() throws Exception {
        var keypair = KeyPairGenerator.getInstance("X448").generateKeyPair();
        kem.validateKeyPair(keypair);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void shouldRejectKeyPairIfPrivateDoesntMatchPublic() {
        kem.validateKeyPair(new KeyPair(aliceKeys.getPublic(), bobKeys.getPrivate()));
    }

    @Test
    public void shouldAcceptValidKeyPairs() {
        kem.validateKeyPair(aliceKeys);
        kem.validateKeyPair(bobKeys);
    }
}