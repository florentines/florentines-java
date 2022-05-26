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

import java.time.Clock;
import java.time.Instant;

import io.florentines.caveat.Caveat.IntegerCaveat;

public final class TemporalCaveat {
    static final String NOT_BEFORE = "nbf";
    static final String EXPIRY = "exp";

    public static IntegerCaveat notBefore(Instant notBefore) {
        return Caveat.integer("nbf", notBefore.getEpochSecond());
    }

    public static IntegerCaveat expiry(Instant expiryTime) {
        return Caveat.integer("exp", expiryTime.getEpochSecond());
    }

    // Caveat TODOs:
    // * Caveat identifiers should be limited to pure printable ASCII, no whitespace, size limited to e.g. 100 bytes
    // * Define rules for processing unrecognised caveats: by default, unknown caveats should be ignored to allow
    // incremental introduction of new mechanisms. Add a "crit" caveat that marks other caveats as critical, in which
    // case if unknown they should cause validation failure.
    // * Standard caveats: exp, nbf, cnf (x5t#S256), aud.
    // * If duplicate caveats then all have to be satisfied
    public static GenericCaveatVerifier<IntegerCaveat> verifier(Clock clock) {
        return new GenericCaveatVerifier<>(IntegerCaveat.class) {
            @Override
            public boolean isSatisfied(CaveatContext context, IntegerCaveat caveat) {
                try {
                    Instant deadline = Instant.ofEpochSecond(caveat.value().longValueExact());
                    Instant now = clock.instant();
                    switch (caveat.key()) {
                    case EXPIRY:
                        return now.isBefore(deadline);
                    case NOT_BEFORE:
                        return !now.isBefore(deadline);
                    }
                    return false;
                } catch (ArithmeticException e) {
                    return false;
                }
            }
        };
    }
}
