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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class Florentine {

    public static SealedFlorentine readFrom(InputStream in) throws IOException {
        throw new UnsupportedOperationException("not implemented");
    }

    public static final class Builder {
        private final DataMap.Builder headers = DataMap.builder();
        private final List<Payload> payloads = new ArrayList<>();

        private DEM dem = DEM.A128SIV_HS256_DEM;

        public Builder header(String key, boolean value) {
            headers.put(key, value);
            return this;
        }

        public Builder header(String key, long value) {
            headers.put(key, value);
            return this;
        }

        public Builder header(String key, String value) {
            headers.put(key, value);
            return this;
        }

        public Builder header(String key, byte[] value) {
            headers.put(key, value);
            return this;
        }

        public Builder header(String key, List<String> value) {
            headers.put(key, value);
            return this;
        }

        public Builder header(String key, Map<String, String> value) {
            headers.put(key, value);
            return this;
        }

        public Builder dem(String dem) {
            this.dem = DEM.get(dem).orElseThrow(() -> new IllegalArgumentException("unknown DEM"));
            return header("dem", dem);
        }

        public Builder payload(MediaType contentType, byte[] content, DataMap headers) {
            payloads.add(new Payload(headers.copy().put("cty", contentType.toCompactString()).build(), content));
            return this;
        }

        public Builder payload(MediaType contentType, byte[] content) {
            return payload(contentType, content, DataMap.empty());
        }

        public Builder json(String json) {
            return payload(MediaType.JSON, json.getBytes(UTF_8));
        }

        public Builder msgpack(byte[] msgPack) {
            return payload(MediaType.MSGPACK, msgPack);
        }

        public SealedFlorentine build() {
            var finalHeaders = headers.build();

            throw new UnsupportedOperationException();
        }
    }

}
