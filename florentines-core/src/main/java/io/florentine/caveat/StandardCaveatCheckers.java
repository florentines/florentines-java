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

import java.time.Instant;
import java.util.Set;


public final class StandardCaveatCheckers {

    static CaveatChecker expiryChecker() {
        return (caveat, context) -> {
            var expiry = Instant.ofEpochSecond(caveat.value().asLong().orElse(Long.MAX_VALUE));
            return context.time().isBefore(expiry);
        };
    }

    static CaveatChecker notBeforeChecker() {
        return (caveat, context) -> {
            var notBefore = Instant.ofEpochSecond(caveat.value().asLong().orElse(Long.MIN_VALUE));
            return !context.time().isBefore(notBefore);
        };
    }

    static CaveatChecker audienceChecker(Set<String> expectedAudience) {
        return (caveat, context) -> {
            var allowedAudience = caveat.value().asListOfStrings().orElseThrow();
            return expectedAudience.stream().anyMatch(allowedAudience::contains);
        };
    }

    static CaveatChecker allowAnythingChecker() {
        return (caveat, context) -> true;
    }

    static CaveatChecker confirmationKeyChecker() {
        return (caveat, context) -> {
            // TODO... this needs to be extensible. Or we ignore the OAuth approach and make each confirmation key
            // its own caveat: x5t, dpop etc
            return false;
        };
    }
}
