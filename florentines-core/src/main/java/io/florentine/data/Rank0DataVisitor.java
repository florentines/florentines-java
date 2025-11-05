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
import java.util.function.LongConsumer;

import static java.util.Objects.requireNonNull;

public interface Rank0DataVisitor {
    void boolValue(boolean value);
    void longValue(long value);
    void textValue(String value);
    void byteValue(byte[] value);

    static FluentVisitor visitor() {
        return new FluentVisitor();
    }

    class FluentVisitor implements Rank0DataVisitor {
        private BooleanConsumer booleanConsumer = it -> {};
        private LongConsumer longConsumer = it -> {};
        private Consumer<String> stringConsumer = it -> {};
        private Consumer<byte[]> bytesConsumer = it -> {};

        public FluentVisitor onBoolean(BooleanConsumer consumer) {
            this.booleanConsumer = requireNonNull(consumer);
            return this;
        }

        public FluentVisitor onLong(LongConsumer consumer) {
            this.longConsumer = requireNonNull(consumer);
            return this;
        }

        public FluentVisitor onString(Consumer<String> consumer) {
            this.stringConsumer = requireNonNull(consumer);
            return this;
        }

        public FluentVisitor onBytes(Consumer<byte[]> consumer) {
            this.bytesConsumer = requireNonNull(consumer);
            return this;
        }

        @Override
        public void boolValue(boolean value) {
            booleanConsumer.accept(value);
        }

        @Override
        public void longValue(long value) {
            longConsumer.accept(value);
        }

        @Override
        public void textValue(String value) {
            stringConsumer.accept(value);
        }

        @Override
        public void byteValue(byte[] value) {
            bytesConsumer.accept(value);
        }
    }
}
