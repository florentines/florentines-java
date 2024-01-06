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

import static io.florentine.caveat.StandardCaveatCheckers.audienceChecker;
import static io.florentine.caveat.StandardCaveatCheckers.expiryChecker;
import static io.florentine.caveat.StandardCaveatCheckers.notBeforeChecker;
import static io.florentine.data.SimpleValue.list;
import static io.florentine.data.SimpleValue.numeric;
import static io.florentine.data.SimpleValue.string;
import static org.assertj.core.api.Assertions.*;

import java.util.Map;
import java.util.Set;

import org.testng.annotations.Test;

import io.florentine.data.SimpleValue;

public class StandardCaveatCheckersTest {

    private static final long TIMESTAMP = 1686571584L;
    private static final Map<String, ? extends SimpleValue> ENVIRONMENT = Map.of(
            AuthContext.NOW, numeric(TIMESTAMP)
    );

    @Test
    public void shouldRejectExpiredToken() {
        var caveat = new Caveat("exp", numeric(TIMESTAMP - 1L), false);
        var context = new AuthContext(Map.of(), Map.of(), Map.of(), ENVIRONMENT);

        var satisfied = expiryChecker().isSatisfied(caveat, context);

        assertThat(satisfied).isFalse();
    }

    @Test
    public void shouldConsiderTimeEqualToExpiryToBeExpired() {
        // We follow JWT (RFC 7519) semantics for "exp" which specifies that the time must be *before* the expiry time.
        var caveat = new Caveat("exp", numeric(TIMESTAMP), false);
        var context = new AuthContext(Map.of(), Map.of(), Map.of(), ENVIRONMENT);

        var satisfied = expiryChecker().isSatisfied(caveat, context);

        assertThat(satisfied).isFalse();
    }

    @Test
    public void shouldRejectTokenUsedBeforeNbf() {
        var caveat = new Caveat("nbf", numeric(TIMESTAMP + 1L), false);
        var context = new AuthContext(Map.of(), Map.of(), Map.of(), ENVIRONMENT);

        var valid = notBeforeChecker().isSatisfied(caveat, context);

        assertThat(valid).isFalse();
    }

    @Test
    public void shouldAllowTokenWhenTimeEqualToNbf() {
        var caveat = new Caveat("nbf", numeric(TIMESTAMP), false);
        var context = new AuthContext(Map.of(), Map.of(), Map.of(), ENVIRONMENT);

        var valid = notBeforeChecker().isSatisfied(caveat, context);

        assertThat(valid).isTrue();
    }

    @Test
    public void shouldRejectTokenIfAudienceDoesntMatchAnyExpected() {
        var expectedAudience = Set.of("a", "b", "c");
        var allowedAudience = list(string("d"), string("e"));
        var caveat = new Caveat("aud", allowedAudience, false);
        var context = new AuthContext(Map.of(), Map.of(), Map.of(), ENVIRONMENT);

        var valid = audienceChecker(expectedAudience).isSatisfied(caveat, context);

        assertThat(valid).isFalse();
    }
}