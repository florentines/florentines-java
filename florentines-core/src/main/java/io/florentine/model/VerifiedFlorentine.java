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

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toUnmodifiableMap;

public final class VerifiedFlorentine extends AbstractFlorentine {
    private final Map<String, Payload> payloads;

    public VerifiedFlorentine(Headers headers, List<Payload> payloads, List<Caveat> caveats, byte[] tag) {
        super(headers, caveats, tag);
        this.payloads = requireNonNull(payloads, "payloads")
                .stream().collect(toUnmodifiableMap(Payload::id, Function.identity()));
    }

    public Optional<Payload> payload(String id) {
        return Optional.ofNullable(payloads.get(id));
    }
}
