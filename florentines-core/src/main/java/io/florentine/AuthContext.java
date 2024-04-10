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

import static java.util.Objects.requireNonNull;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.net.ssl.SSLSession;

/**
 * Represents the context in which Florentine caveats are being verified. This includes the current time, any
 * SSL (TLS) session that exists over which the request is being processed, and details about the current logged-in
 * user (if already authenticated). Note that Florentine caveats are evaluated before the contents of the payload are
 * trusted, so if the Florentine is itself being used to convey authentication information, then the authenticated user
 * will be unknown at the point of caveat checking. Thus, the authenticated user field in this class is intended for
 * holding information relating to a user authenticated by some other means, such as client certificate, OpenID
 * Connect, SAML, session cookie, etc.
 */
public final class AuthContext {

    private final Clock clock;
    private final SSLSession sslSession;
    private final AuthenticatedUser user;

    private AuthContext(Builder builder) {
        this.clock = builder.clock;
        this.sslSession = builder.sslSession;
        this.user = builder.user;
    }

    /**
     * Constructs a builder for initialising an authentication context.
     *
     * @return a builder object.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * If the request is occurring over a secure channel, then this returns the SSL session information about that
     * channel.
     *
     * @return the SSL session information, if available.
     */
    public Optional<SSLSession> getSslSession() {
        return Optional.ofNullable(sslSession);
    }

    /**
     * If authenticated user information is available then this method returns information about the user and how
     * they were authenticated.
     *
     * @return the authenticated user information, if available.
     */
    public Optional<AuthenticatedUser> getAuthenticatedUser() {
        return Optional.ofNullable(user);
    }

    /**
     * Returns the system clock to use for determining the current time. By default, this is the
     * {@linkplain Clock#systemUTC() UTC system clock}.
     *
     * @return the system clock.
     */
    public Clock getClock() {
        return clock;
    }

    /**
     * Provides information about the current user and how they were authenticated.
     */
    public interface AuthenticatedUser {
        /**
         * A unique identifier for the user. This is not guaranteed to have any particular format, but must be unique
         * for each distinct user of the system.
         *
         * @return a unique identifier for the user.
         */
        String getUniqueID();

        /**
         * A set of identifiers for methods that were <em>successfully</em> used to authenticate the user, for
         * example password or biometrics. The values that can appear in the list are application-specific, but
         * <a href="https://www.rfc-editor.org/rfc/rfc8176">RFC 8176</a> defines a list of standard values. This
         * corresponds to the "amr" value in florentine:connect and OpenID Connect.
         *
         * @return the set of methods used to authenticate the user.
         */
        Set<String> getAuthenticationMethods();

        /**
         * The Authentication Context Class Reference (acr) that applies to the authentication of the user. This is
         * typically a URI or other identifier that indicates the Level of Assurance (LoA) achieved by the whole
         * authentication process, in reference to some formal spec.
         *
         * @return the ACR value.
         */
        String getAuthenticationClass();

        /**
         * The time at which the user was last actively authenticated.
         *
         * @return the last authentication time.
         */
        Instant getAuthenticationTime();

        /**
         * A set of attributes identifying the user supplied by the authentication service. May be empty.
         *
         * @return the user attributes.
         */
        Map<String, List<String>> getAttributes();
    }

    public static class Builder {
        private SSLSession sslSession;
        private AuthenticatedUser user;
        private Clock clock = Clock.systemUTC();

        public Builder sslSession(SSLSession sslSession) {
            this.sslSession = requireNonNull(sslSession);
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = requireNonNull(clock);
            return this;
        }

        public Builder authenticatedUser(AuthenticatedUser user) {
            this.user = requireNonNull(user);
            return this;
        }

        public AuthContext build() {
            return new AuthContext(this);
        }
    }
}
