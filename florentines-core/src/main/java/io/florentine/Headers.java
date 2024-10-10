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

import static org.msgpack.value.ValueFactory.newString;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import org.msgpack.core.MessagePack;
import org.msgpack.value.ImmutableValue;
import org.msgpack.value.ValueFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.mail.internet.ContentType;
import jakarta.mail.internet.ParseException;

public final class Headers extends Record {
    private static final Logger log = LoggerFactory.getLogger(Headers.class);

    private final Map<String, ImmutableValue> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    Headers() {
        super(Type.HEADER, Flag.CRITICAL);
    }

    private Headers header(String headerName, ImmutableValue value) {
        var old = headers.putIfAbsent(headerName, value);
        if (old != null && !old.equals(value)) {
            throw new IllegalStateException("Header has already been set");
        }
        return this;
    }

    public Optional<String> stringHeader(String headerName) {
        return Optional.ofNullable(headers.get(headerName)).map(h -> h.asStringValue().asString());
    }

    Headers contentType(ContentType contentType) {
        var cty = contentType.toString();
        if (cty.startsWith("application/")) { // Save space
            cty = cty.substring("application/".length());
        }
        return header("cty", newString(cty));
    }

    public Optional<ContentType> contentType() {
        return stringHeader("cty")
                .map(cty -> !cty.contains("/") ? "application/" + cty : cty)
                .flatMap(Headers::parseContentType);
    }

    @Override
    byte[] publicContent() {
        try (var packer = MessagePack.newDefaultBufferPacker()) {
            var mapBuilder = ValueFactory.newMapBuilder();
            headers.forEach((key, value) -> mapBuilder.put(newString(key), value));
            mapBuilder.build().writeTo(packer);
            return packer.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Optional<ContentType> parseContentType(String contentType) {
        try {
            return Optional.of(new ContentType(contentType));
        } catch (ParseException e) {
            log.error("Unable to parse content type: {}", contentType, e);
            return Optional.empty();
        }
    }
}
