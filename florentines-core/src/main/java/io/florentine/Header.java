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
import java.util.TreeMap;
import java.util.regex.Pattern;

import org.msgpack.core.MessagePack;
import org.msgpack.value.ImmutableValue;
import org.msgpack.value.ValueFactory;

final class Header extends Record {
    // See https://www.rfc-editor.org/rfc/rfc6838#section-4.2
    private static final Pattern MEDIA_TYPE_PATTERN =
            Pattern.compile("([a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]{0,126}/)?([a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]{0,126})");

    private final Map<String, ImmutableValue> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    Header() {
        super(Type.HEADER, Flag.CRITICAL);
    }

    private Header header(String headerName, ImmutableValue value) {
        var old = headers.putIfAbsent(headerName, value);
        if (old != null && !old.equals(value)) {
            throw new IllegalStateException("Header has already been set");
        }
        return this;
    }

    public Header contentType(String contentType) {
        var match = MEDIA_TYPE_PATTERN.matcher(contentType);
        if (!match.matches()) {
            throw new IllegalArgumentException("Invalid media type");
        }
        if ("application/".equals(match.group(1))) {
            contentType = match.group(2); // Strip application/ prefix to save space
        }
        return header("cty", newString(contentType));
    }

    @Override
    public byte[] publicContent() {
        try (var packer = MessagePack.newDefaultBufferPacker()) {
            var mapBuilder = ValueFactory.newMapBuilder();
            headers.forEach((key, value) -> mapBuilder.put(newString(key), value));
            mapBuilder.build().writeTo(packer);
            return packer.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
