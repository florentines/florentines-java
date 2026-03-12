/*
 * Copyright 2025-2026 Neil Madden.
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

import io.florentine.crypto.DestroyableSecretKey;
import io.florentine.dem.DEM;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

public final class Florentine {

    private final DEM dem;
    private final byte[]        kemdata;
    private final DataMap headers;
    private final List<Payload> content;
    private final List<Caveat>  caveats;
    private DestroyableSecretKey caveatKey;

    private Florentine(byte[] kemdata,
                       DataMap headers,
                       List<Payload> content,
                       List<Caveat> caveats,
                       byte[] tag,
                       DEM dem) {
        this.kemdata = kemdata;
        this.headers = headers;
        this.content = content;
        this.caveats = caveats;
        this.caveatKey = dem.importKey(tag);
        this.dem = dem;
    }

    public Florentine restrict(Caveat caveat) {

        // FIXME: just a sketch currently
        try (var key = caveatKey) {
            var encaps = dem.encapsulate(key, caveat.publicData(), caveat.secretData());
            caveats.add(caveat);
            this.caveatKey = encaps.key();
        }

        return this;
    }

    public Florentine copy() {
        return new Florentine(kemdata.clone(), headers, content, caveats, caveatKey.getEncoded(), dem);
    }

    // TODO: Payload -> SealedPayload, Caveat -> SealedCaveat
    record Payload(DataMap headers, byte[] content) {}
    public record Caveat(String predicate, DataMap parameters, byte[] secret) {
        public Caveat {
            Require.notBlank(predicate, "predicate");
            requireNonNull(parameters, "parameters");
            secret = secret == null ? null : secret.clone();
        }
        public Caveat(String predicate, DataMap parameters) {
            this(predicate, parameters, null);
        }

        List<byte[]> publicData() {
            return List.of(predicate.getBytes(UTF_8), parameters.toBytes());
        }

        List<byte[]> secretData() {
            return secret == null ? List.of() : List.of(secret);
        }
    }

    public static class Builder {
        private static final String DEM_HEADER = "dem";

        private final DataMap.Builder headers = DataMap.builder();
        private final List<Payload> content = new ArrayList<>(1);
        private final List<Caveat> caveats = new ArrayList<>();

        private DEM dem = DEM.getDefault();
        private byte[] demKey = Bytes.secureRandom(32);

        @Deprecated // Remind me to remove this...
        public Builder demKey(byte[] demKey) {
            this.demKey = demKey.clone();
            return this;
        }

        public Builder header(String key, String value) {
            headers.put(key, value);
            return this;
        }

        public Builder dem(DEM dem) {
            this.dem = requireNonNull(dem);
            return this;
        }

        public PayloadBuilder payload() {
            return new PayloadBuilder(this);
        }

        public Florentine build() {
            var finalHeaders = headers.put(DEM_HEADER, dem.identifier()).build();
            return new Florentine(null, finalHeaders, content, caveats, demKey, dem);
        }
    }

    public static class PayloadBuilder {
        public static final String APPLICATION_PREFIX = "application/";
        private final Builder parent;
        private final DataMap.Builder headers = DataMap.builder();
        private byte[] content;

        PayloadBuilder(Builder parent) {
            this.parent = parent;
        }

        public PayloadBuilder header(String key, String value) {
            headers.put(key, value);
            return this;
        }

        public PayloadBuilder content(String contentType, byte[] content) {
            if (contentType.startsWith(APPLICATION_PREFIX)) {
                contentType = contentType.substring(APPLICATION_PREFIX.length());
            }
            header("cty", contentType);
            this.content = content.clone();
            return this;
        }

        public PayloadBuilder json(String json) {
            return content("application/json", json.getBytes(UTF_8));
        }

        public Builder done() {
            if (content == null) {
                throw new IllegalStateException("content has not been set");
            }
            parent.content.add(new Payload(headers.build(), content));
            return parent;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Florentine that)) { return false; }
        return Objects.equals(dem, that.dem) &&
                Objects.deepEquals(kemdata, that.kemdata) &&
                Objects.equals(headers, that.headers) &&
                Objects.equals(content, that.content) &&
                Objects.equals(caveats, that.caveats) &&
                Objects.equals(caveatKey, that.caveatKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(dem, Arrays.hashCode(kemdata), headers, content, caveats, caveatKey);
    }
}
