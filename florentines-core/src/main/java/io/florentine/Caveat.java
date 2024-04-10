/*
 * Copyright 2024 Neil Madden.
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

import static org.msgpack.value.ValueFactory.newArray;
import static org.msgpack.value.ValueFactory.newMap;
import static org.msgpack.value.ValueFactory.newString;
import static org.msgpack.value.ValueFactory.newTimestamp;

import java.net.URI;
import java.time.Instant;
import java.util.Collection;

import org.msgpack.value.ImmutableValue;
import org.msgpack.value.ValueFactory;

record Caveat(String predicate, ImmutableValue details) {

    /**
     * From RFC 6749:<pre>{@code
     *      scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
     * }</pre>
     */
    private static final String SCOPE_PATTERN = "[!#-\\[\\]-~]+";

    // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
    // "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
    // token = 1*tchar
    private static final String TOKEN_PATTERN = "[!#$%&'*+.^_`|~0-9a-zA-Z-]+";

    public static Caveat expiresAt(Instant expiry) {
        return new Caveat("exp", newTimestamp(expiry));
    }

    public static Caveat notBefore(Instant startTime) {
        return new Caveat("nbf", newTimestamp(startTime));
    }

    public static Caveat audience(Collection<String> audience) {
        return new Caveat("aud", newArray(audience.stream().map(ValueFactory::newString).toList()));
    }

    public static Caveat certificateThumbprintS256(byte[] hash) {
        if (hash == null || hash.length != 32) {
            throw new IllegalArgumentException("Invalid SHA-256 certificate thumbprint");
        }
        return new Caveat("cnf", newMap(newString("x5t#S256"), newString(Base64url.encode(hash))));
    }

    public static Caveat certificateThumbprintS512(byte[] hash) {
        if (hash == null || hash.length != 64) {
            throw new IllegalArgumentException("Invalid SHA-512 certificate thumbprint");
        }
        return new Caveat("cnf", newMap(newString("x5t#S512"), newString(Base64url.encode(hash))));
    }

    public static Caveat scope(Collection<String> scope) {
        if (scope == null || !scope.stream().allMatch(s -> s.matches(SCOPE_PATTERN))) {
            throw new IllegalArgumentException("Invalid scope");
        }
        return new Caveat("scope", newString(String.join(" ", scope)));
    }

    public static Caveat httpMethod(String method) {
        if (!method.matches(TOKEN_PATTERN)) {
            throw new IllegalArgumentException("Invalid HTTP method");
        }
        return new Caveat("htm", newString(method));
    }

    public static Caveat httpUrl(String url) {
        return httpUrl(URI.create(url));
    }

    public static Caveat httpUrl(URI url) {
        if (!url.isAbsolute()) {
            throw new IllegalArgumentException("URL must be absolute");
        }
        if (url.getRawFragment() != null || url.getRawQuery() != null) {
            throw new IllegalArgumentException("URL must not have query or fragment");
        }
        return new Caveat("htu", newString(url.toString()));
    }
}
