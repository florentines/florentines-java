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

public record Caveat(DataMap parameters, boolean isCritical) {

    public Caveat {
        if (parameters.size() != 1) {
            throw new IllegalArgumentException("only one caveat allowed");
        }
    }

    Pair<SealedCaveat, DataEncapsulationKey> seal(DataEncapsulationKey key, DEM dem) {
        throw new UnsupportedOperationException();
    }

    public static Caveat critical(DataMap parameters) {
        return new Caveat(parameters, true);
    }

    public Caveat advisory() {
        return new Caveat(parameters, false);
    }

    public Caveat critical() {
        return new Caveat(parameters, true);
    }

    public static Caveat expiresAt(Instant expiry) {
        return critical(DataMap.of("exp", expiry.getEpochSecond()));
    }

    public static Caveat notBefore(Instant notBeforeTime) {
        return critical(DataMap.of("nbf", notBeforeTime.getEpochSecond()));
    }

    public static Caveat audience(String... audience) {
        return critical(DataMap.of("aud", List.of(audience)));
    }

    public static Caveat scope(String... allowedScopes) {
        return critical(DataMap.of("scope", List.of(allowedScopes)));
    }

    public static Caveat httpMethod(String... allowedMethods) {
        return critical(DataMap.of("htm", List.of(allowedMethods)));
    }

    public static Caveat httpPath(String... allowedPaths) {
        return critical(DataMap.of("htp", List.of(allowedPaths)));
    }

    public static Caveat certificateThumbprint(X509Certificate certificate) {
        try {
            return critical(DataMap.of("x5t#S256", Crypto.sha256(certificate.getEncoded())));
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
