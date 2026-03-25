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
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import static java.nio.charset.StandardCharsets.*;

public record Caveat(String type, DataMap parameters) {

    public Caveat {
        if (parameters.size() != 1) {
            throw new IllegalArgumentException("only one caveat allowed");
        }
        if (!parameters.containsKey(type)) {
            throw new IllegalArgumentException("type doesn't match parameters");
        }
    }

    SealedCaveat seal(DEM.Encapsulator encapsulator) {
        var encrypted = parameters.toByteArray();
        var siv = encapsulator.encapsulate(List.of(type.getBytes(UTF_8)), List.of(encrypted));
        return new SealedCaveat(encrypted, siv);
    }

    public static Caveat caveat(DataMap parameters) {
        return new Caveat(parameters.firstKey(), parameters);
    }

    public static Caveat criticalCaveatTypes(List<String> caveats) {
        return caveat(DataMap.of("crit", caveats));
    }

    public static Caveat expiresAt(Instant expiry) {
        return caveat(DataMap.of("exp", expiry.getEpochSecond()));
    }

    public static Caveat notBefore(Instant notBeforeTime) {
        return caveat(DataMap.of("nbf", notBeforeTime.getEpochSecond()));
    }

    public static Caveat audience(String... audience) {
        return caveat(DataMap.of("aud", List.of(audience)));
    }

    public static Caveat scope(String... allowedScopes) {
        return caveat(DataMap.of("scope", List.of(allowedScopes)));
    }

    public static Caveat httpMethod(String... allowedMethods) {
        return caveat(DataMap.of("htm", List.of(allowedMethods)));
    }

    public static Caveat httpPath(String... allowedPaths) {
        return caveat(DataMap.of("htp", List.of(allowedPaths)));
    }

    public static Caveat certificateThumbprint(X509Certificate certificate) {
        try {
            return caveat(DataMap.of("x5t#S256", Crypto.sha256(certificate.getEncoded())));
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
