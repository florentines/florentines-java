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

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;

import org.testng.annotations.Test;

public class CaveatVerifierTest {

    @Test
    public void testUglyCast() {
        var verifier = TemporalCaveat.verifier(Clock.systemUTC());
        var caveat = Caveat.integer("exp", 12345);
        assertThat(CaveatVerifier.cast(caveat, verifier)).isPresent();

        var badCaveat = Caveat.string("exp", "foo");
        assertThat(CaveatVerifier.cast(badCaveat, verifier)).isEmpty();
    }

}