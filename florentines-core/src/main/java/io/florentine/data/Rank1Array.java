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

import java.util.function.Consumer;

import static io.florentine.data.Rank1DataVisitor.visitor;
import static java.util.Objects.requireNonNull;

public final class Rank1Array implements Rank0DataVisitor {
    private final Rank2Array items = new Rank2Array();

    public static Rank1Array of(Object... items) {
        return new Rank1Array().add(items);
    }

    public Rank1Array add(Object... items) {
        new Rank2Array().add(items).forEach(visitor()
                .onArray(reject())
                .onMap(reject()));
        this.items.add(items);
        return this;
    }

    private static <T> Consumer<T> reject() {
        return it -> { throw new IllegalArgumentException("invalid value"); };
    }

    @Override
    public void boolValue(boolean value) {
        items.boolValue(value);
    }

    @Override
    public void longValue(long value) {
        items.longValue(value);
    }

    @Override
    public void textValue(String value) {
        items.textValue(requireNonNull(value));
    }

    @Override
    public void byteValue(byte[] value) {
        items.byteValue(value);
    }

    public void forEach(Rank0DataVisitor visitor) {
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
