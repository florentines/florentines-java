/*
 * Copyright 2023 Neil Madden.
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

package io.florentine.caveat;

import static io.florentine.caveat.StandardCaveatCheckers.expiryChecker;
import static io.florentine.caveat.StandardCaveatCheckers.notBeforeChecker;
import static io.florentine.data.SimpleValue.numeric;
import static org.assertj.core.api.Assertions.*;

import java.time.Instant;
import java.util.Map;

import org.testng.annotations.Test;

public class StandardCaveatCheckersTest {

    public static final long TIMESTAMP = 1686571584L;

    @Test
    public void shouldRejectExpiredToken() {
        long expiry = TIMESTAMP;
        var now = Instant.ofEpochSecond(expiry + 1L);
        var caveat = new Caveat("exp", numeric(expiry), false);
        var context = new AuthContext(now, Map.of(), Map.of(), Map.of());

        var satisfied = expiryChecker().checkSatisfied(caveat, context);

        assertThat(satisfied).isFalse();
    }

    @Test
    public void shouldConsiderTimeEqualToExpiryToBeExpired() {
        // We follow JWT (RFC 7519) semantics for "exp" which specifies that the time must be *before* the expiry time.
        long expiry = TIMESTAMP;
        var now = Instant.ofEpochSecond(expiry); // now == expiry
        var caveat = new Caveat("exp", numeric(expiry), false);
        var context = new AuthContext(now, Map.of(), Map.of(), Map.of());

        var satisfied = expiryChecker().checkSatisfied(caveat, context);

        assertThat(satisfied).isFalse();
    }

    @Test
    public void shouldRejectTokenUsedBeforeNbf() {
        long nbf = TIMESTAMP;
        var now = Instant.ofEpochSecond(nbf - 1L);
        var caveat = new Caveat("nbf", numeric(nbf), false);
        var context = new AuthContext(now, Map.of(), Map.of(), Map.of());

        var valid = notBeforeChecker().checkSatisfied(caveat, context);

        assertThat(valid).isFalse();
    }

    @Test
    public void shouldAllowTokenWhenTimeEqualToNbf() {
        long nbf = TIMESTAMP;
        var now = Instant.ofEpochSecond(nbf);
        var caveat = new Caveat("nbf", numeric(nbf), false);
        var context = new AuthContext(now, Map.of(), Map.of(), Map.of());

        var valid = notBeforeChecker().checkSatisfied(caveat, context);

        assertThat(valid).isTrue();
    }
}