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

package io.florentine.crypto;


import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class CC20HS512Test {

    private final CC20HS512 dem = CC20HS512.INSTANCE;

    private DestroyableSecretKey key;

    @BeforeMethod
    public void createKey() {
        var keyData = new byte[32];
        Arrays.fill(keyData, (byte) 42);
        key = dem.importKey(keyData);
    }

    @Test
    public void shouldHaveCorrectIdentifier() {
        assertThat(dem.identifier()).isEqualTo("CC20-HS512");
    }

    @Test
    public void shouldHaveCorrectKeyWrapIdenfifier() {
        assertThat(dem.asKeyWrapCipher().algorithm()).isEqualTo("CC20SIV-HS512");
    }

    @Test
    public void shouldRoundTrip() {
        var parts = List.of(new TestPart("test".getBytes(UTF_8), new byte[] { 'A' }, true));
        var tagAndKey = dem.encrypt(key, parts);
        dem.decrypt(key, parts, tagAndKey.tag()).orElseThrow();
    }

    record TestPart(byte[] content, byte[] header, boolean isEncrypted) implements DEM.Part {}
}