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

import java.util.Map;
import java.util.function.BiConsumer;

import static io.florentine.data.Rank1EntryVisitor.visitor;

public final class Rank1Map implements Rank0EntryVisitor {
    private final Rank2Map items = new Rank2Map();

    public Rank1Map putAll(Map<String, Object> items) {
        new Rank2Map().putAll(items).forEach(visitor().onMap(reject()).onArray(reject()));
        this.items.putAll(items);
        return this;
    }

    private static <T> BiConsumer<String, T> reject() {
        return (key, value) -> { throw new IllegalArgumentException("invalid value"); };
    }

    public Rank1Map put(String key, Object value) {
        return putAll(Map.of(key, value));
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

    public void forEach(Rank0EntryVisitor visitor) {
        items.forEach(visitor()
                .onBoolean(visitor::boolValue)
                .onLong(visitor::longValue)
                .onString(visitor::textValue)
                .onBytes(visitor::byteValue));
    }

    public int size() {
        return items.size();
    }
}
