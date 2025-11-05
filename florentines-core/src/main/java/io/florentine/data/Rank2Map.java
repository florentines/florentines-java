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

public final class Rank2Map implements Rank1EntryVisitor {
    private final Map<String, Object> items = new LinkedHashMap<>();

    public Rank2Map putAll(Map<String, Object> items) {
        visitAll(items, this);
        return this;
    }

    public Rank2Map put(String key, Object item) {
        return putAll(Map.of(key, item));
    }

    @Override
    public void rank1Array(String key, Rank1Array array) {
        items.put(key, array);
    }

    @Override
    public void rank1Map(String key, Rank1Map map) {
        items.put(key, map);
    }

    @Override
    public void boolValue(String key, boolean value) {
        items.put(key, value);
    }

    @Override
    public void longValue(String key, long value) {
        items.put(key, value);
    }

    @Override
    public void textValue(String key, String value) {
        items.put(key, value);
    }

    @Override
    public void byteValue(String key, byte[] value) {
        items.put(key, value);
    }

    public void forEach(Rank1EntryVisitor visitor) {
        visitAll(items, visitor);
    }

    private static void visitAll(Map<String, Object> items, Rank1EntryVisitor visitor) {
        items.forEach((key, value) -> {
            if (value instanceof Boolean b) {
                visitor.boolValue(key, b);
            } else if (value instanceof Long l) {
                visitor.longValue(key, l);
            } else if (value instanceof String s) {
                visitor.textValue(key, s);
            } else if (value instanceof byte[] b) {
                visitor.byteValue(key, b);
            } else if (value instanceof Rank1Array a) {
                visitor.rank1Array(key, a);
            } else if (value instanceof Rank1Map m) {
                visitor.rank1Map(key, m);
            } else {
                throw new IllegalArgumentException("invalid value: " + value.getClass());
            }
        });
    }

    public int size() {
        return items.size();
    }
}
