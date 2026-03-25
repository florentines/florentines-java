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

import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public final class StandardCaveatVerifier implements CaveatVerifier {
    private static final CaveatVerifier ALWAYS_SATISFIED = (caveat, context) -> true;
    private final Map<String, CaveatVerifier> verifiers;

    public static CaveatVerifier expiryVerifier() {
        return (caveat, context) -> {
            var expiry = Instant.ofEpochSecond(caveat.parameters().getLong("exp").
                    orElseThrow(() -> new InvalidCaveatException("exp")));
            return context.requestTime().isBefore(expiry);
        };
    }

    public static CaveatVerifier notBeforeTimeVerifier() {
        return (caveat, context) -> {
            var expiry = Instant.ofEpochSecond(caveat.parameters().getLong("nbf").
                    orElseThrow(() -> new InvalidCaveatException("nbf")));
            return context.requestTime().isAfter(expiry);
        };
    }

    public static CaveatVerifier audienceVerifier() {
        return (caveat, context) -> {
            var allowedAudience = caveat.parameters().getList("aud")
                    .orElseThrow(() -> new InvalidCaveatException("aud"));
            return allowedAudience.contains(context.targetAudience());
        };
    }

    private CaveatVerifier criticalCaveatVerifier() {
        return (caveat, context) -> {
            var criticalTypes = caveat.parameters().getList("crit")
                    .orElseThrow(() -> new InvalidCaveatException("crit"));
            return verifiers.keySet().containsAll(criticalTypes);
        };
    }

    public static CaveatVerifier scopeVerifier() {
        return (caveat, context) -> {
            var allowedScopes = caveat.parameters().getList("scope")
                    .orElseThrow(() -> new InvalidCaveatException("scope"));
            return context.requestScope().stream().anyMatch(allowedScopes::contains);
        };
    }

    public static CaveatVerifier httpMethodVerifier() {
        return (caveat, context) -> {
            var allowedMethods = caveat.parameters().getList("htm")
                    .orElseThrow(() -> new InvalidCaveatException("htm"));
            return context.httpMethod().map(allowedMethods::contains).orElse(false);
        };
    }

    public static CaveatVerifier httpPathVerifier() {
        return (caveat, context) -> {
            var allowedPaths = caveat.parameters().getList("htp")
                    .orElseThrow(() -> new InvalidCaveatException("htp"));
            return allowedPaths.contains(context.requestUri().getRawPath());
        };
    }

    public static CaveatVerifier certificateThumbprintVerifier() {
        return (caveat, context) -> {
            var expectedHash = caveat.parameters().getBytes("x5t#S256")
                    .orElseThrow(() -> new InvalidCaveatException("x5t#S256"));
            if (expectedHash.length != 32) {
                throw new InvalidCaveatException("invalid SHA-256 certificate thumbprint");
            }
            return context.clientCertificate()
                    .map(cert -> {
                        try {
                            return Crypto.sha256(cert.getEncoded());
                        } catch (CertificateEncodingException e) {
                            return new byte[0];
                        }
                    })
                    .map(hash -> Arrays.equals(expectedHash, hash)) // NB: public values, no timing attacks
                    .orElse(false);
        };
    }

    private StandardCaveatVerifier(Map<String, CaveatVerifier> verifiers) {
        this.verifiers = requireNonNull(verifiers, "verifiers");
    }

    public StandardCaveatVerifier() {
        this.verifiers = Map.of(
                "exp", expiryVerifier(),
                "nbf", notBeforeTimeVerifier(),
                "crit", criticalCaveatVerifier(),
                "aud", audienceVerifier(),
                "scope", scopeVerifier(),
                "htm", httpMethodVerifier(),
                "htp", httpPathVerifier(),
                "x5t#S256", certificateThumbprintVerifier()
        );
    }

    public StandardCaveatVerifier withVerifier(String caveatType, CaveatVerifier verifier) {
        var newVerifiers = new HashMap<>(verifiers);
        if (newVerifiers.putIfAbsent(requireNonNull(caveatType, "caveatType"), requireNonNull(verifier, "verifier"))
                != null) {
            throw new IllegalStateException("Verifier already registered for type: " + caveatType);
        }
        return new StandardCaveatVerifier(Map.copyOf(newVerifiers));
    }

    @Override
    public boolean isSatisfied(Caveat caveat, RequestContext context) {
        // Unrecognised caveats are ignored (always satisfied) unless marked as critical
        return verifiers.getOrDefault(caveat.parameters().firstKey(), ALWAYS_SATISFIED).isSatisfied(caveat, context);
    }

    public static final class InvalidCaveatException extends RuntimeException {
        InvalidCaveatException(String message) {
            super(message);
        }
    }
}
