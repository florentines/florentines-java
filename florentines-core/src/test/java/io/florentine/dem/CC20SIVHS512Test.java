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

package io.florentine.dem;

import io.florentine.crypto.DestroyableSecretKey;
import org.assertj.core.api.Condition;
import org.testng.annotations.Test;

import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.function.Predicate.not;
import static org.assertj.core.api.Assertions.assertThat;

public class CC20SIVHS512Test {

    @Test
    public void shouldRoundtrip() {
        // given
        var dem = CC20SIVHS512.INSTANCE;
        var key = new DestroyableSecretKey(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
                                          16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31}, "CC20SIV-HS512");
        var pub = List.of("Some Assoc Data".getBytes(UTF_8));
        var sec = List.of("Foo".getBytes(UTF_8), "Bar".getBytes(UTF_8));

        // when
        var encaps = dem.encapsulate(key, pub, sec);
        var result = dem.decapsulate(key, pub, sec, encaps.tag());

        // then
        assertThat(result).isPresent()
                .hasValueSatisfying(new Condition<>(not(DestroyableSecretKey::isDestroyed), "not destroyed"))
                .hasValue(encaps.key());
    }


}