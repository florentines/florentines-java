/*
 * Copyright 2025 Neil Madden.
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

import io.florentine.DestroyableSecretKey;
import org.testng.annotations.Test;

import java.io.FileOutputStream;
import java.io.InvalidClassException;
import java.io.ObjectOutputStream;

import static org.assertj.core.api.Assertions.*;

public class DestroyableSecretKeyTest {
    private static final byte[] KEY_BYTES = new byte[] {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            -127, -126, -125, -124, -123, -122, -121, -120,
            -119, -118, -117, -116, -115, -114, -113, -112
    };

    @Test(expectedExceptions = InvalidClassException.class,
            expectedExceptionsMessageRegExp = "not serializable")
    public void shouldPreventSerialization() throws Exception {
        var key = new DestroyableSecretKey(KEY_BYTES, "Test");
        new ObjectOutputStream(new FileOutputStream("/dev/null")).writeObject(key);
    }

    @Test
    public void shouldSupportPemFormat() {
        try (var key = new DestroyableSecretKey(KEY_BYTES, "Test")) {
            assertThat(key.getEncoded("PEM")).asString()
                    .isEqualTo("-----BEGIN SECRET KEY-----\r\n" +
                            "AAECAwQFBgcICQoLDA0OD4GCg4SFhoeIiYqLjI2Oj5A=\r\n" +
                            "-----END SECRET KEY-----");
        }
    }
}