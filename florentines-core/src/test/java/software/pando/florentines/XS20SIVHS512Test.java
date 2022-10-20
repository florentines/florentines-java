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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

import javax.crypto.SecretKey;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class XS20SIVHS512Test {

    private DEM dem;

    @BeforeMethod
    public void setup() {
        dem = new XS20SIVHS512();
    }

    @Test
    public void testBasicOperation() {
        byte[] keyMaterial = new byte[32];
        Arrays.fill(keyMaterial, (byte) 42);
        SecretKey key = dem.key(keyMaterial);

        String message = "Hello, World!";
        byte[] payload = message.getBytes(UTF_8);
        byte[] context = "Alice -> Bob".getBytes(UTF_8);

        CompletableFuture<SecretKey> chainingKey = new CompletableFuture<>();

        byte[] siv = dem.authenticate(key, context, payload).chainingKey(chainingKey::complete).andEncrypt(payload);
        assertThat(context).asString().isEqualTo("Alice -> Bob");

        SecretKey finalChainingKey = dem.decrypt(key, siv, payload).andVerify(context, payload).orElseThrow();
        assertThat(payload).asString().isEqualTo(message);
        assertThat(finalChainingKey).isEqualTo(chainingKey.join());
    }
}