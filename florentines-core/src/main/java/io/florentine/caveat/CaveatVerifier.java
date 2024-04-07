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

package io.florentine.caveat;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLPeerUnverifiedException;

import org.msgpack.core.MessagePackException;
import org.msgpack.value.ValueFactory;

import io.florentine.Base64url;

public final class CaveatVerifier {

    private static final Map<String, CaveatChecker> STANDARD_CHECKERS = Map.of(
            "exp", expiryChecker(),
            "nbf", notBeforeChecker(),
            "aud", audienceChecker(),
            "cnf", confirmationKeyChecker(),
            "htm", httpMethodChecker(),
            "htu", httpUriChecker()
    );

    private static final Map<String, CaveatChecker> STANDARD_CONFIRMATION_METHODS = Map.of(
            "x5t#S256", new ThumbprintChecker("SHA-256"),
            "x5t#S512", new ThumbprintChecker("SHA-512")
    );

    private final Map<String, CaveatChecker> checkers = new ConcurrentHashMap<>(STANDARD_CHECKERS);

    public List<Caveat> verifyCaveats(List<Caveat> caveats, AuthContext context, Request request) {
        var unsatisfiedCaveats = new ArrayList<Caveat>();
        for (var caveat : caveats) {
            var checker = checkers.getOrDefault(caveat.predicate(), alwaysFalseChecker());
            try {
                if (!checker.isSatisfied(caveat, context, request)) {
                    unsatisfiedCaveats.add(caveat);
                }
            } catch (MessagePackException e) {
                // Caveat is malformed - treat it as unsatisfied
                unsatisfiedCaveats.add(caveat);
            }
        }
        return unsatisfiedCaveats;
    }

    private static CaveatChecker expiryChecker() {
        return (caveat, context, request) -> {
            var exp = caveat.details().asTimestampValue().toInstant();
            return request.getRequestTime().isBefore(exp);
        };
    }

    private static CaveatChecker notBeforeChecker() {
        return (caveat, context, request) -> {
            var nbf = caveat.details().asTimestampValue().toInstant();
            return !request.getRequestTime().isBefore(nbf);
        };
    }

    private static CaveatChecker audienceChecker() {
        return (caveat, context, request) -> {
            var requestUri = request.getRequestUri();
            var port = requestUri.getPort();
            if (port == -1) {
                if ("http".equals(requestUri.getScheme())) {
                    port = 80;
                } else if ("https".equals(requestUri.getScheme())) {
                    port = 443;
                }
            }
            var origin = requestUri.getScheme() + "://" + requestUri.getHost() + ":" + port;
            return caveat.details().asArrayValue().list().contains(ValueFactory.newString(origin));
        };
    }

    private static ConfirmationKeyChecker confirmationKeyChecker() {
        return new ConfirmationKeyChecker();
    }

    private static CaveatChecker httpMethodChecker() {
        return (caveat, context, request) -> {
            var expectedMethod = caveat.details().asStringValue().asString();
            var providedMethod = request.getRequestMethod();
            return expectedMethod.equals(providedMethod);
        };
    }

    private static CaveatChecker httpUriChecker() {
        return (caveat, context, request) -> {
            try {
                var expectedUri = new URI(caveat.details().asStringValue().asString());
                var requestUri = request.getRequestUri();
                return normalizeUriWithoutQueryOrFragment(expectedUri)
                        .equals(normalizeUriWithoutQueryOrFragment(requestUri));
            } catch (URISyntaxException e) {
                return false;
            }
        };
    }

    private static URI normalizeUriWithoutQueryOrFragment(URI uri) throws URISyntaxException {
        // Normalize ports for http/https URIs
        int port = uri.getPort();
        if (port == -1) {
            port = switch (uri.getScheme().toLowerCase(Locale.ROOT)) {
                case "http"     ->  80;
                case "https"    -> 443;
                default         ->  -1;
            };
        }
        return new URI(uri.getScheme(), null, uri.getHost(), port, uri.getPath(), null, null);
    }


    private static CaveatChecker alwaysFalseChecker() {
        return (caveat, context, request) -> false;
    }

    private static class ConfirmationKeyChecker implements CaveatChecker {
        private final Map<String, CaveatChecker> confirmationMethods =
                new ConcurrentHashMap<>(STANDARD_CONFIRMATION_METHODS);

        @Override
        public boolean isSatisfied(Caveat caveat, AuthContext context, Request request) {
            var confirmationKeys = caveat.details().asMapValue();
            if (confirmationKeys == null) {
                return true;
            }

            for (var entry : confirmationKeys.entrySet()) {
                var method = entry.getKey().asStringValue().asString();
                var checker = confirmationMethods.getOrDefault(method, alwaysFalseChecker());
                var subCaveat = new Caveat(method, entry.getValue().immutableValue());
                if (!checker.isSatisfied(subCaveat, context, request)) {
                    return false;
                }
            }

            return true;
        }
    }

    private static class ThumbprintChecker implements CaveatChecker {

        private final MessageDigest hash;

        ThumbprintChecker(String hashAlgorithm) {
            try {
                this.hash = MessageDigest.getInstance(hashAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public boolean isSatisfied(Caveat caveat, AuthContext context, Request request) {
            final var expectedHash = Base64url.decode(caveat.details().asStringValue().asString());
            return context.getSslSession().map(session -> {
                try {
                    var certs = session.getPeerCertificates();
                    if (certs != null && certs[0] instanceof X509Certificate leafCert) {
                        var data = leafCert.getEncoded();
                        synchronized (hash) {
                            var computedHash = hash.digest(data);
                            return MessageDigest.isEqual(computedHash, expectedHash);
                        }
                    }
                } catch (SSLPeerUnverifiedException | CertificateEncodingException e) {
                    return false;
                }
                return false;
            }).orElse(false);
        }
    }
}
