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

package io.florentine.model;

import io.florentine.DEM;

import java.util.List;

import static java.util.Objects.requireNonNull;

sealed abstract class AbstractFlorentine permits SealedFlorentine, VerifiedFlorentine {
    private final Headers headers;
    private final List<Caveat> caveats;
    private final byte[] tag;

    AbstractFlorentine(Headers headers, List<Caveat> caveats, byte[] tag) {
        this.headers = requireNonNull(headers, "headers");
        this.caveats = List.copyOf(requireNonNull(caveats, "caveats"));
        this.tag = requireNonNull(tag, "tag").clone();
    }

    AbstractFlorentine(AbstractFlorentine toCopy) {
        this(toCopy.headers, toCopy.caveats, toCopy.tag);
    }

    public void restrict(Caveat caveat) {

        // TODO
    }
}
