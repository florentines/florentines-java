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

package io.florentine;

import io.florentine.crypto.CryptoUtils;
import io.florentine.crypto.DestroyableSecretKey;
import io.florentine.dem.CommittingDEM;

import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class Florentine {

    private final CommittingDEM dem;
    private final byte[]        preamble;
    private final Headers       headers;
    private final List<Payload> content;
    private final List<Caveat>  caveats;
    private DestroyableSecretKey caveatKey;

    private Florentine(byte[] preamble,
                       Headers headers,
                       List<Payload> content,
                       List<Caveat> caveats,
                       byte[] tag,
                       CommittingDEM dem) {
        this.preamble = preamble;
        this.headers = headers;
        this.content = content;
        this.caveats = caveats;
        this.caveatKey = dem.importKey(tag);
        this.dem = dem;
    }

    public Florentine restrict(Caveat caveat) {

        // FIXME: just a sketch currently
        try (var key = caveatKey) {
            var encaps = dem.encapsulate(key, List.of(caveat.toString().getBytes(UTF_8)), List.of());
            this.caveatKey = encaps.key();
        }

        return this;
    }

    record Payload(String id, Headers headers, byte[] content) {}
    record Caveat() {}

    public static class Builder {
        private final Headers.Builder headers = Headers.builder();
        private final List<Payload> content = new ArrayList<>(1);
        private final List<Caveat> caveats = new ArrayList<>();

        public Builder header(String key, String value) {
            headers.header(key, value);
            return this;
        }

        public Builder dem(CommittingDEM dem) {
            return header("dem", dem.getIdentifier());
        }

        public PayloadBuilder payload(String id) {
            return new PayloadBuilder(this, id);
        }

        public Florentine build() {
            var demAlg = headers.build().getString("dem").orElse("CC20SIV-HS512");
            return new Florentine(null, headers.build(), content, caveats, null, null);
        }
    }

    public static class PayloadBuilder {
        public static final String APPLICATION_PREFIX = "application/";
        private final String id;
        private final Builder parent;
        private final Headers.Builder headers = Headers.builder();
        private byte[] content;

        PayloadBuilder(Builder parent, String id) {
            this.parent = parent;
            this.id = Require.notBlank(id, "id");
        }

        public PayloadBuilder header(String key, String value) {
            headers.header(key, value);
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
            return content("application/json;charset=utf-8", json.getBytes(UTF_8));
        }

        public Builder done() {
            if (content == null) {
                throw new IllegalStateException("content has not been set");
            }
            parent.content.add(new Payload(id, headers.build(), content));
            return parent;
        }
    }

}
