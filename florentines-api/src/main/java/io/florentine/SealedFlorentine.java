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

package io.florentine;

import java.util.ArrayList;
import java.util.List;

public final class SealedFlorentine {
    private final DEM dem;
    private final byte[] preamble;
    private final DataMap headers;
    private final List<SealedPayload> payloads;
    private final List<SealedCaveat> caveats;

    private DataEncapsulationKey key;

    SealedFlorentine(DEM dem,
                     byte[] preamble,
                     DataMap headers,
                     List<SealedPayload> payloads,
                     List<SealedCaveat> caveats,
                     DataEncapsulationKey key) {
        this.dem = dem;
        this.preamble = preamble;
        this.headers = headers;
        this.payloads = payloads;
        this.caveats = caveats;
        this.key = key;
    }

    public SealedFlorentine restrict(Caveat caveat) {
        try (var encapsulator = dem.beginEncapsulation(key)) {
            var sealed = caveat.seal(encapsulator);
            caveats.add(sealed);
            this.key = encapsulator.done();
        }
        return this;
    }

    public SealedFlorentine copy() {
        return new SealedFlorentine(dem, preamble.clone(), headers, payloads, new ArrayList<>(caveats), key.copy());
    }
}
