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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.SoftAssertions.assertSoftly;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.IntStream;

import javax.crypto.SecretKey;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class SIVTest {
    public static final String EXPECTED_CIPHERTEXT =
            "b8f6326563976488bb3802112c19fc4997063530b3f495b2b648b384e2c1d8debdb9f5c8191b36c00eb2b2aa";
    private KeyWrapper keyWrapper;
    private SecretKey wrapKey;
    private DestroyableSecretKey keyToWrap;

    @BeforeMethod
    public void setup() {
        keyWrapper = new SIV(StreamCipher.CHACHA20, PRF.HS512);
        var keyBytes = new byte[32];
        Arrays.fill(keyBytes, (byte) 42);
        wrapKey = new DestroyableSecretKey(keyBytes, keyWrapper.identifier());

        IntStream.range(0, 32).forEach(i -> keyBytes[i] = (byte) i);
        keyToWrap = new DestroyableSecretKey(keyBytes, "AES");
    }

    @Test
    public void shouldHaveCorrectIdentifier() {
        assertThat(keyWrapper.identifier()).isEqualTo("CC20SIV-HS512");
    }

    @Test
    public void shouldBeDeterministic() {
        assertThat(keyWrapper.wrap(wrapKey, keyToWrap)).asHexString()
                .isEqualToIgnoringCase(
                        EXPECTED_CIPHERTEXT);
    }

    @Test
    public void shouldDecrypt() {
        var wrapped = HexFormat.of().parseHex(EXPECTED_CIPHERTEXT);
        var unwrapped = keyWrapper.unwrap(wrapKey, wrapped, "AES");
        assertThat(unwrapped).hasValue(keyToWrap);
    }

    @Test
    public void shouldIncludeTheKeyAlgorithmInAssocData() {
        var wrapped = HexFormat.of().parseHex(EXPECTED_CIPHERTEXT);
        var unwrapped = keyWrapper.unwrap(wrapKey, wrapped, "Not AES");
        assertThat(unwrapped).isEmpty();
    }

    @Test
    public void shouldDetectTamperingAtAnyBitPosition() {
        var wrapped = HexFormat.of().parseHex(EXPECTED_CIPHERTEXT);
        assertSoftly(softly -> {
            for (int i = 0; i < wrapped.length; ++i) {
                for (int j = 0; j < 8; ++j) {
                    var clone = wrapped.clone();
                    clone[i] ^= (byte) (1 << j);
                    var unwrapped = keyWrapper.unwrap(wrapKey, clone, "AES");
                    softly.assertThat(unwrapped).isEmpty();
                }
            }
        });
    }
}