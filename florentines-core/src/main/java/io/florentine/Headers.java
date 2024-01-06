/*
 * Copyright 2023 Neil Madden.
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

import static io.florentine.Utils.rejectUnless;
import static io.florentine.data.SimpleValue.NullValue.NULL;
import static io.florentine.data.SimpleValue.string;

import java.io.ByteArrayInputStream;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;

import io.florentine.data.SimpleValue;

public final class Headers {

    private static final String RESTRICTED_NAME = "[A-Za-z0-9][A-Za-z0-9!#$&.^_+-]{0,126}";
    private static final Pattern MEDIATYPE_PATTERN = Pattern.compile(RESTRICTED_NAME + "/" + RESTRICTED_NAME);
    private final Map<String, SimpleValue> headers = new ConcurrentHashMap<>();

    public Headers() {
    }

    Headers(Map<String, SimpleValue> headers) {
        this.headers.putAll(headers);
    }

    static Optional<Headers> parse(byte[] headerData) {
        var headers = new Headers();
        try {
            var obj = JsonParser.object().from(new ByteArrayInputStream(headerData));
            for (var entry : obj.entrySet()) {
                var converted = SimpleValue.convert(entry.getValue());
                if (converted.isEmpty()) {
                    return Optional.empty();
                }
                headers.headers.put(entry.getKey(), converted.get());
            }
            return Optional.of(headers);
        } catch (JsonParserException e) {
            return Optional.empty();
        }
    }

    public Headers header(String header, String value) {
        headers.put(header, string(value));
        return this;
    }

    public Optional<String> header(String header) {
        return headers.getOrDefault(header, NULL).asString();
    }

    public Headers compression(Compression compression) {
        return header("zip", compression.identifier());
    }

    public Compression compression() {
        return Compression.valueOf(header("zip").orElse("DEF"));
    }

    public Headers contentType(String contentType) {
        rejectUnless(MEDIATYPE_PATTERN.matcher(contentType).matches(), "not a valid media-type");
        return header("cty", contentType.replaceAll("^application/", ""));
    }

    public String contentType() {
        var cty = header("cty").orElse("application/json");
        return cty.contains("/") ? "application/" + cty : cty;
    }
}
