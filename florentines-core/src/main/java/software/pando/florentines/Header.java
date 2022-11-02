/*
 * Copyright 2022 Neil Madden.
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

package software.pando.florentines;

import static java.util.Objects.requireNonNull;

import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

final class Header {
    private final Map<String, String> headers = new TreeMap<>();

    public Header compression(Compression compression) {
        if (compression != Compression.NONE) {
            headers.put("zip", compression.identifier);
        } else {
            headers.remove("zip");
        }
        return this;
    }

    public Compression compression() {
        return Compression.of(headers.get("zip"));
    }

    public Header contentType(MediaType contentType) {
        headers.put("cty", requireNonNull(contentType).toString());
        return this;
    }

    public Optional<MediaType> contentType() {
        return MediaType.parse(headers.get("cty"));
    }

    public Header header(String header, String value) {
        headers.put(requireNonNull(header), requireNonNull(value));
        return this;
    }

    public String header(String header) {
        return headers.get(header);
    }

    public Map<String, String> asMap() {
        return headers;
    }

    public String toString() {
        return headers.toString();
    }
}
