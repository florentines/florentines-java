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
        PrivateIdentity alice = algorithm.generateKeys("test", "alice");
        PrivateIdentity bob = algorithm.generateKeys("test", "bob");

        // When
        var original = Florentine.builder(algorithm, alice, bob.getPublicIdentity())
                .compressionAlgorithm(Compression.DEFLATE)
                .compressedPayload("hello".getBytes(UTF_8))
                .encryptedPayload("world".getBytes(UTF_8))
                .compressedEncryptedPayload("other".getBytes(UTF_8))
                .build();

        System.out.println("Original: " + original);
        System.out.println("Size: " + original.toString().length() + " (raw bytes = " + Base64url.decode(original.toString()).length + ")");

        // Then
        var decoded = Florentine.fromString(algorithm, original.toString()).orElseThrow();
        var packets = decoded.decrypt(bob, alice.getPublicIdentity()).orElseThrow();
        assertThat(packets).hasSize(4);

        var reply = decoded.reply().encryptedPayload("goodbyte".getBytes(UTF_8)).build().toString();
        System.out.println("Reply: " + reply);
        System.out.println("Size: " + reply.length() + " (raw bytes = " + Base64url.decode(reply).length + ")");

        decoded = Florentine.fromString(algorithm, reply).orElseThrow();
        packets = decoded.decryptReplyTo(original).orElseThrow();
        assertThat(packets).hasSize(2);
        assertThat(packets.get(1)).asString(UTF_8).isEqualTo("\u0011goodbyte");
    }
}