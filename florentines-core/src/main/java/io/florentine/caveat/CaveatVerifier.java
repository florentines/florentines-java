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

import static java.util.Collections.unmodifiableSet;
import static java.util.Objects.requireNonNull;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import io.florentine.Payload;

public final class CaveatVerifier {

    private static final CaveatChecker CRITICAL_CHECKER = (caveat, context) -> !caveat.critical();
    private final Map<String, CaveatChecker> caveatCheckers = new ConcurrentHashMap<>(Map.of(
            "exp", StandardCaveatCheckers.expiryChecker(),
            "nbf", StandardCaveatCheckers.notBeforeChecker(),
            "aud", StandardCaveatCheckers.allowAnythingChecker()
    ));

    private final Set<Caveat> unsatisfiedCaveats;
    private final List<Payload> payloads;

    public CaveatVerifier(Set<Caveat> unsatisfiedCaveats, List<Payload> payloads) {
        this.unsatisfiedCaveats = requireNonNull(unsatisfiedCaveats);
        this.payloads = requireNonNull(payloads);
    }

    public CaveatVerifier withoutStandardCaveatCheckers() {
        caveatCheckers.remove("exp");
        caveatCheckers.remove("nbf");
        caveatCheckers.remove("aud");
        return this;
    }

    public CaveatVerifier withCaveatChecker(String caveatType, CaveatChecker checker) {
        caveatCheckers.put(caveatType, checker);
        return this;
    }

    public CaveatVerifier withExpectedAudience(Collection<String> expectedAudience) {
        caveatCheckers.put("aud", StandardCaveatCheckers.audienceChecker(Set.copyOf(expectedAudience)));
        return this;
    }

    public Set<Caveat> getUnsatisfiedCaveats() {
        return unmodifiableSet(unsatisfiedCaveats);
    }

    public Optional<List<Payload>> verify(AuthContext context) {
        for (var it = unsatisfiedCaveats.iterator(); it.hasNext();) {
            var caveat = it.next();
            var checker = caveatCheckers.getOrDefault(caveat.predicate(), CRITICAL_CHECKER);
            if (checker.isSatisfied(caveat, context)) {
                it.remove();
            }
        }

        return unsatisfiedCaveats.isEmpty() ? Optional.of(payloads) : Optional.empty();
    }
}
