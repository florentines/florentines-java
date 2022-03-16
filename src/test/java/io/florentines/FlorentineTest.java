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

public class FlorentineTest {

    @Test
    public void testIt() {
        // Given
        Algorithm algorithm = Algorithm.AUTHKEM_X25519_HKDF_A256SIV_HS256;
        SecretKey alice = algorithm.generateKeys("test");
        SecretKey bob = algorithm.generateKeys("test");
        SecretKey charlie = algorithm.generateKeys("test");

        // When
        var florentine = Florentine.builder(algorithm, alice, bob.getPublicIdentity())
                .compressionAlgorithm(Compression.DEFLATE)
                .payload(false, true, "hello".getBytes(UTF_8))
                .encryptedPayload("world".getBytes(UTF_8))
                .build();

        System.out.println("Original: " + florentine);
        System.out.println("Size: " + florentine.toString().length() + " (raw bytes = " + Base64url.decode(florentine.toString()).length + ")");

        // Then
        var decoded = Florentine.fromString(algorithm, florentine.toString()).orElseThrow();
        var packets = decoded.decrypt(bob, alice.getPublicIdentity()).orElseThrow();
        assertThat(packets).hasSize(3);

        var reply = decoded.reply().encryptedPayload("goodbyte".getBytes(UTF_8)).build().toString();
        System.out.println("Reply: " + reply);
        System.out.println("Size: " + reply.length() + " (raw bytes = " + Base64url.decode(reply).length + ")");

        decoded = Florentine.fromString(algorithm, reply).orElseThrow();
        packets = decoded.decryptReply(florentine).orElseThrow();
        assertThat(packets).hasSize(2);
        assertThat(packets.get(1)).asString(UTF_8).isEqualTo("\u0011goodbyte");
    }
}