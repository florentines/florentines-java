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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Florentine {
    private static final Logger logger = LoggerFactory.getLogger(Florentine.class);

    static {
        logger.debug("Initializing standard algorithms");
        KEM.register(new X25519Kem(new SIV(StreamCipher.CHACHA20, PRF.HS512)));
        Compression.register(Compression.Deflate.INSTANCE);
    }

    public static class Builder {
        private final Headers headers = new Headers();
        private final List<Payload> payloads = new ArrayList<>();

        PayloadBuilder payload(byte[] content) {
            return new PayloadBuilder(content);
        }

        public class PayloadBuilder {
            private final Map<String, String> headers = new LinkedHashMap<>();
            private final byte[] content;

            PayloadBuilder(byte[] content) {
                this.content = content;
            }

            public PayloadBuilder header(String name, String value) {
                var old = headers.putIfAbsent(name, value);
                if (old != null) {
                    throw new IllegalStateException("Header already set");
                }
                return this;
            }

            public PayloadBuilder contentType(MediaType contentType) {
                return header("cty", contentType.toString(true));
            }

            public Builder build() {
                var payload = new Payload(headers, content);
                payloads.add(payload);
                return Builder.this;
            }
        }
    }
}
