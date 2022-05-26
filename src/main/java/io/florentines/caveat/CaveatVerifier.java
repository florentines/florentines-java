/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines.caveat;

import static java.util.Collections.unmodifiableList;
import static java.util.Collections.unmodifiableMap;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.groupingBy;

import java.time.Clock;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import io.florentines.Payload;
import io.florentines.caveat.Caveat.ArrayCaveat;

public final class CaveatVerifier {
    private final Map<String, List<Caveat>> unsatisfiedCaveats;
    private final CaveatContext context;
    private final Payload payload;

    CaveatVerifier(CaveatContext context, Collection<Caveat> unsatisfiedCaveats, Payload payload) {
        this.unsatisfiedCaveats = new ConcurrentHashMap<>(unsatisfiedCaveats.stream().collect(groupingBy(Caveat::key)));
        this.context = requireNonNull(context, "context");
        this.payload = requireNonNull(payload, "payload");
    }

    public <T extends Caveat> CaveatVerifier satisfy(String caveatType, GenericCaveatVerifier<T> verifier) {
        unsatisfiedCaveats.computeIfPresent(caveatType, (key, caveats) -> removeSatisfiedCaveats(caveats, verifier));
        return this;
    }

    private <T extends Caveat> List<Caveat> removeSatisfiedCaveats(List<Caveat> caveats,
            GenericCaveatVerifier<T> verifier) {
        caveats.removeIf(caveat -> cast(caveat, verifier).map(c -> verifier.isSatisfied(context, c)).orElse(false));
        return caveats.isEmpty() ? null : caveats;
    }

    @SuppressWarnings("unchecked")
    static <T extends Caveat> Optional<T> cast(Caveat caveat, GenericCaveatVerifier<T> verifier) {
        if (verifier.caveatSubType.isInstance(caveat)) {
            return Optional.of(verifier.caveatSubType.cast(caveat));
        } else {
            return Optional.empty();
        }
    }

    public CaveatVerifier satisfyTemporalCaveats(Clock clock) {
        var verifier = TemporalCaveat.verifier(clock);
        return satisfy(TemporalCaveat.NOT_BEFORE, verifier).satisfy(TemporalCaveat.EXPIRY, verifier);
    }

    public CaveatVerifier satisfyAudience(Set<String> expectedAudience) {
        return satisfy("aud", new GenericCaveatVerifier<>(ArrayCaveat.class) {
            @Override
            public boolean isSatisfied(CaveatContext context, ArrayCaveat caveat) {
                return caveat.value().stream().anyMatch(expectedAudience::contains);
            }
        });
    }

    public CaveatVerifier satisfyAudience(String expectedAudience) {
        return satisfyAudience(Set.of(expectedAudience));
    }

    public Optional<Payload> verify() {
        return unsatisfiedCaveats.isEmpty() ? Optional.of(payload) : Optional.empty();
    }

    public Map<String, List<Caveat>> unsatisfiedCaveats() {
        Map<String, List<Caveat>> copy = new LinkedHashMap<>();
        unsatisfiedCaveats.forEach((key, value) -> {
            copy.put(key, unmodifiableList(value));
        });
        return unmodifiableMap(copy);
    }

}
