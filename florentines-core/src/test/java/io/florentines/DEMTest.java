/*
 * Copyright 2026 Neil Madden.
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

package io.florentines;

import org.testng.annotations.Test;

import static java.nio.charset.StandardCharsets.*;
import static org.assertj.core.api.Assertions.*;

public class DEMTest {

    @Test
    public void shouldRoundTrip() {
        var dem = DEM.INSTANCE;
        var key = dem.freshKey();
        var msg = "A test message";
        var ctx = "Some context string";

        var plaintext = msg.getBytes(UTF_8);
        var tag1 = dem.encapsulate(key, plaintext, ctx.getBytes(UTF_8));
        var tag2 = dem.decapsulate(key, plaintext, ctx.getBytes(UTF_8));
        assertThat(plaintext).asString().isEqualTo(msg);
        assertThat(tag2).isEqualTo(new DestroyableSecretKey("foo", tag1.getEncoded()));
    }

}