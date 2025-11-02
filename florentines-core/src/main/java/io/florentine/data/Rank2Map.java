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
import java.util.Objects;

import static java.util.Objects.requireNonNull;

public final class Rank2Map {
    final Map<String, Object> map = new LinkedHashMap<>();

    public static Rank2Map of(Object... keyValuePairs) {
        if (keyValuePairs.length % 2 != 0) {
            throw new IllegalArgumentException("Odd number of arguments");
        }
        var result = new Rank2Map();
        for (int i = 0; i < keyValuePairs.length; i += 2) {
            var key = (String) keyValuePairs[i];
            var value = keyValuePairs[i + 1];

            if (value instanceof Boolean b) {
                result.put(key, b);
            } else if (value instanceof Number n) {
                if (n.doubleValue() == n.longValue()) {
                    result.put(key, n.longValue());
                } else {
                    result.put(key, n.doubleValue());
                }
            } else if (value instanceof String s) {
                result.put(key, s);
            } else if (value instanceof byte[] bytes) {
                result.put(key, bytes);
            } else if (value instanceof Rank1Array array) {
                result.put(key, array);
            } else if (value instanceof Rank1Map m) {
                result.put(key, m);
            } else {
                throw new IllegalArgumentException("invalid value for Rank2Map: " + value);
            }
        }
        return result;
    }

    public Rank2Map put(String key, boolean value) {
        map.put(key, value);
        return this;
    }

    public Rank2Map put(String key, long value) {
        map.put(key, value);
        return this;
    }

    public Rank2Map put(String key, double value) {
        map.put(key, value);
        return this;
    }

    public Rank2Map put(String key, String value) {
        map.put(key, requireNonNull(value));
        return this;
    }

    public Rank2Map put(String key, byte[] value) {
        map.put(key, value.clone());
        return this;
    }

    public Rank2Map put(String key, Rank1Array array) {
        map.put(key, Objects.requireNonNull(array));
        return this;
    }

    public Rank2Map put(String key, Rank1Map map) {
        this.map.put(key, Objects.requireNonNull(map));
        return this;
    }

    public <E extends Exception> void forEach(Rank2MapVisitor<E> visitor) throws E {
        for (var entry : map.entrySet()) {
            var key = entry.getKey();
            var value = entry.getValue();
            if (value instanceof Boolean b) {
                visitor.bool(key, b);
            } else if (value instanceof Long l) {
                visitor.integer(key, l);
            } else if (value instanceof Double d) {
                visitor.num(key, d);
            } else if (value instanceof String s) {
                visitor.text(key, s);
            } else if (value instanceof byte[] bytes) {
                visitor.bytes(key, bytes);
            } else if (value instanceof Rank1Array array) {
                visitor.rank1Array(key, array);
            } else if (value instanceof Rank1Map m) {
                visitor.rank1Map(key, m);
            } else {
                throw new AssertionError("unreachable");
            }
        }
    }

    public int size() {
        return map.size();
    }

    @Override
    public String toString() {
        return "Rank2Map" + map;
    }
}
