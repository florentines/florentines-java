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

package io.florentine.data;

import java.util.LinkedHashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public final class Rank1Map {
    private final Map<String, Object> map = new LinkedHashMap<>();

    public Rank1Map put(String key, boolean value) {
        map.put(key, value);
        return this;
    }

    public Rank1Map put(String key, double value) {
        map.put(key, value);
        return this;
    }

    public Rank1Map put(String key, String value) {
        map.put(key, requireNonNull(value));
        return this;
    }

    public Rank1Map put(String key, byte[] value) {
        map.put(key, value.clone());
        return this;
    }

    public <E extends Exception> void forEach(Rank1MapVisitor<E> visitor) throws E {
        for (var entry : map.entrySet()) {
            var key = entry.getKey();
            var value = entry.getValue();
            if (value instanceof Boolean b) {
                visitor.bool(key, b);
            } else if (value instanceof Double d) {
                visitor.num(key, d);
            } else if (value instanceof String s) {
                visitor.text(key, s);
            } else if (value instanceof byte[] bytes) {
                visitor.bytes(key, bytes);
            } else {
                throw new AssertionError("unreachable");
            }
        }
    }

    public int size() {
        return map.size();
    }
}
