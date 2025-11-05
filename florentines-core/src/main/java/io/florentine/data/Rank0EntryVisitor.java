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

import java.util.function.BiConsumer;

import static java.util.Objects.requireNonNull;

public interface Rank0EntryVisitor {
    void boolValue(String key, boolean value);
    void longValue(String key, long value);
    void textValue(String key, String value);
    void byteValue(String key, byte[] value);

    static FluentVisitor visitor() {
        return new FluentVisitor();
    }

    class FluentVisitor implements Rank0EntryVisitor {
        private BiConsumer<String, Boolean> booleanConsumer = (k, v) -> {};
        private BiConsumer<String, Long> longConsumer = (k, v) -> {};
        private BiConsumer<String, String> stringConsumer = (k, v) -> {};
        private BiConsumer<String, byte[]> bytesConsumer = (k, v) -> {};

        public FluentVisitor onBoolean(BiConsumer<String, Boolean> consumer) {
            this.booleanConsumer = requireNonNull(consumer);
            return this;
        }

        public FluentVisitor onLong(BiConsumer<String, Long> consumer) {
            this.longConsumer = requireNonNull(consumer);
            return this;
        }

        public FluentVisitor onString(BiConsumer<String, String> consumer) {
            this.stringConsumer = requireNonNull(consumer);
            return this;
        }

        public FluentVisitor onBytes(BiConsumer<String, byte[]> consumer) {
            this.bytesConsumer = requireNonNull(consumer);
            return this;
        }

        @Override
        public void boolValue(String key, boolean value) {
            booleanConsumer.accept(key, value);
        }

        @Override
        public void longValue(String key, long value) {
            longConsumer.accept(key, value);
        }

        @Override
        public void textValue(String key, String value) {
            stringConsumer.accept(key, value);
        }

        @Override
        public void byteValue(String key, byte[] value) {
            bytesConsumer.accept(key, value);
        }
    }
}
