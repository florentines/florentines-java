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

import java.util.Arrays;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class SyntheticIVModeTest {

    private DestroyableSecretKey wrapKey;
    private DestroyableSecretKey keyToWrap;

    @BeforeMethod
    public void createKey() {
        var keyBytes = new byte[32];
        Arrays.fill(keyBytes, (byte) 42);
        wrapKey = new DestroyableSecretKey(keyBytes, "ChaCha20");
        Arrays.fill(keyBytes, (byte) 43);
        keyToWrap = new DestroyableSecretKey(keyBytes, "AES");
    }

    @Test
    public void shouldRoundTrip() {
        var cipher = KeyWrapCipher.CC20SIV_HS512;
        var wrapped = cipher.wrap(wrapKey, keyToWrap, "test".getBytes(UTF_8));
        assertThat(wrapped).hasSize(48);
        var unwrapped = cipher.unwrap(wrapKey, wrapped, "AES", "test".getBytes(UTF_8)).orElseThrow();
        assertThat(unwrapped).isEqualTo(keyToWrap);
    }
}