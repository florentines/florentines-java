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

import io.florentine.CC20HS512;
import io.florentine.Compression;
import io.florentine.DEM;
import io.florentine.KEM;

import java.io.Serial;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * A florentine in the sealed state, where all payload data is encrypted and inaccessible.
 */
public final class SealedFlorentine extends AbstractFlorentine {
    private final byte[] kemData;
    private final Headers headers;
    private final byte[] encryptedPayload;
    private final byte[] payloadTag;
    private byte[] tag;

    public SealedFlorentine(byte[] kemData, Headers headers, byte[] encryptedPayload, byte[] payloadTag) {
        super(headers, List.of(), payloadTag); // FIXME
        this.kemData = kemData;
        this.headers = headers;
        this.encryptedPayload = encryptedPayload;
        this.payloadTag = payloadTag;
    }


    public VerificationResult verify(VerificationContext context) throws FlorentineAuthenticationFailure {
        throw new FlorentineAuthenticationFailure();
    }

    public record VerificationResult(Optional<VerifiedFlorentine> florentine, List<Caveat> unsatisfiedCaveats) {
        public VerificationResult {
            requireNonNull(florentine, "florentine");
            requireNonNull(unsatisfiedCaveats, "caveats");
            if (florentine.isEmpty() && unsatisfiedCaveats.isEmpty()) {
                throw new IllegalArgumentException("Must specify Florentine or unsatisfied caveats");
            }
        }

        public Optional<Payload> verifiedPayload(String id) {
            return florentine.flatMap(fl -> fl.payload(id));
        }

        public boolean isVerified() {
            return florentine.isPresent();
        }
    }

    public static class FlorentineAuthenticationFailure extends RuntimeException {
        @Serial
        private static final long serialVersionUID = 1L;

        public FlorentineAuthenticationFailure() {
            // NB: deliberately no details specified
            super("Florentine authentication failed");
        }
    }

    public static final class Builder {
        private KEM kem = KEM.get(KEM.X25519_CC20SIV_HS512).orElseThrow();
        private DEM dem = CC20HS512.INSTANCE;
        private Compression compression = Compression.get(Compression.DEFLATE).orElseThrow();
        private final Headers.Builder headers = Headers.builder();

        public Builder kem(KEM kem) {
            this.kem = requireNonNull(kem);
            return this;
        }

        public Builder dem(DEM dem) {
            this.dem = requireNonNull(dem);
            headers.header("dem", dem.identifier());
            return this;
        }

        public Builder compression(Compression compression) {
            this.compression = requireNonNull(compression);
            headers.header("zip", compression.identifier());
            return this;
        }

        public SealedFlorentine build() {
            var header = headers.build();
            return new SealedFlorentine(null, null, null, null);
        }
    }
}
