/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines;

import static java.util.Objects.requireNonNull;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonWriter;

public final class Header {
    public static final String CONTENT_TYPE = "cty";
    public static final String COMPRESSION_ALGORITHM = "zip";
    public static final String IN_REPLY_TO = "irt";

    private final JsonObject headers;

    Header(JsonObject headers) {
        this.headers = requireNonNull(headers);
    }

    public Optional<String> contentType() {
        return string(CONTENT_TYPE);
    }

    public Compression compressionAlgorithm() {
        return Compression.valueOf(
                string(COMPRESSION_ALGORITHM).orElse(Compression.NONE.getIdentifier()));
    }

    public Optional<String> inReplyTo() {
        return string(IN_REPLY_TO);
    }

    public boolean isReply() {
        return inReplyTo().isPresent();
    }

    public Optional<String> string(String key) {
        return Optional.ofNullable(headers.getString(key));
    }

    public Map<String, Object> asMap() {
        return headers;
    }

    JsonObject asJson() {
        return headers;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) { return true; }
        if (!(other instanceof Header)) { return false; }
        Header that = (Header) other;
        return this.headers.equals(that.headers);
    }

    @Override
    public int hashCode() {
        return Objects.hash(headers);
    }

    @Override
    public String toString() {
        return JsonWriter.string(headers);
    }
}
