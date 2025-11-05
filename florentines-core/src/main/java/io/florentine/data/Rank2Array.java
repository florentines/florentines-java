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
import java.util.Objects;

public final class Rank2Array implements Rank1DataVisitor {
    private final List<Object> items = new ArrayList<>();

    public static Rank2Array of(Object... items) {
        return new Rank2Array().add(items);
    }

    public Rank2Array add(Object... items) {
        visitAll(List.of(items), this);
        return this;
    }

    @Override
    public void rank1Array(Rank1Array array) {
        items.add(Objects.requireNonNull(array));
    }

    @Override
    public void rank1Map(Rank1Map map) {
        items.add(Objects.requireNonNull(map));
    }

    @Override
    public void boolValue(boolean value) {
        items.add(value);
    }

    @Override
    public void longValue(long value) {
        items.add(value);
    }

    @Override
    public void textValue(String value) {
        items.add(value);
    }

    @Override
    public void byteValue(byte[] value) {
        items.add(value);
    }

    public void forEach(Rank1DataVisitor visitor) {
        visitAll(items, visitor);
    }

    private static void visitAll(List<Object> items, Rank1DataVisitor visitor) {
        for (var item : items) {
            if (item instanceof Boolean b) {
                visitor.boolValue(b);
            } else if (item instanceof Long l) {
                visitor.longValue(l);
            } else if (item instanceof String s) {
                visitor.textValue(s);
            } else if (item instanceof byte[] b) {
                visitor.byteValue(b);
            } else if (item instanceof Rank1Array a) {
                visitor.rank1Array(a);
            } else if (item instanceof Rank1Map m) {
                visitor.rank1Map(m);
            } else {
                throw new IllegalArgumentException("invalid item: " + item.getClass());
            }
        }
    }

    public int size() {
        return items.size();
    }
}
