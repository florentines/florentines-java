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

import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

public final class Rank2Array {
    private final List<Object> items = new ArrayList<>();

    public static Rank2Array of(Object... args) {
        var result = new Rank2Array();
        for (var value : args) {
            if (value instanceof Boolean b) {
                result.add(b);
            } else if (value instanceof Double d) {
                result.add(d);
            } else if (value instanceof String s) {
                result.add(s);
            } else if (value instanceof byte[] bytes) {
                result.add(bytes);
            } else if (value instanceof Rank1Array array) {
                result.add(array);
            } else if (value instanceof Rank1Map m) {
                result.add(m);
            } else {
                throw new IllegalArgumentException("invalid value for Rank2Array: " + value);
            }
        }
        return result;
    }

    public Rank2Array add(boolean value) {
        items.add(value);
        return this;
    }

    public Rank2Array add(double value) {
        items.add(value);
        return this;
    }

    public Rank2Array add(String value) {
        items.add(requireNonNull(value));
        return this;
    }

    public Rank2Array add(byte[] value) {
        items.add(value.clone());
        return this;
    }

    public Rank2Array add(Rank1Array array) {
        items.add(requireNonNull(array));
        return this;
    }

    public Rank2Array add(Rank1Map map) {
        items.add(requireNonNull(map));
        return this;
    }

    public int size() {
        return items.size();
    }

    public <E extends Exception> void forEach(Rank2ArrayVisitor<E> visitor) throws E {
        for (var item : items) {
            if (item instanceof Boolean b) {
                visitor.bool(b);
            } else if (item instanceof Double d) {
                visitor.num(d);
            } else if (item instanceof String s) {
                visitor.text(s);
            } else if (item instanceof byte[] bytes) {
                visitor.bytes(bytes);
            } else if (item instanceof Rank1Array array) {
                visitor.rank1Array(array);
            } else if (item instanceof Rank1Map map) {
                visitor.rank1Map(map);
            } else {
                throw new AssertionError("unreachable");
            }
        }
    }
}
