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

public interface Rank1DataVisitor extends Rank0DataVisitor {
    void rank1Array(Rank1Array array);
    void rank1Map(Rank1Map map);

    static FluentVisitor visitor() {
        return new FluentVisitor();
    }

    class FluentVisitor extends Rank0DataVisitor.FluentVisitor implements Rank1DataVisitor {
        private Consumer<Rank1Array> arrayConsumer = it -> {};
        private Consumer<Rank1Map> mapConsumer = it -> {};

        public Rank1DataVisitor.FluentVisitor onArray(Consumer<Rank1Array> consumer) {
            this.arrayConsumer = requireNonNull(consumer);
            return this;
        }

        public Rank1DataVisitor.FluentVisitor onMap(Consumer<Rank1Map> consumer) {
            this.mapConsumer = requireNonNull(consumer);
            return this;
        }

        @Override
        public Rank1DataVisitor.FluentVisitor onBoolean(BooleanConsumer consumer) {
            return (Rank1DataVisitor.FluentVisitor) super.onBoolean(consumer);
        }

        @Override
        public Rank1DataVisitor.FluentVisitor onLong(LongConsumer consumer) {
            return (Rank1DataVisitor.FluentVisitor) super.onLong(consumer);
        }

        @Override
        public Rank1DataVisitor.FluentVisitor onString(Consumer<String> consumer) {
            return (Rank1DataVisitor.FluentVisitor) super.onString(consumer);
        }

        @Override
        public Rank1DataVisitor.FluentVisitor onBytes(Consumer<byte[]> consumer) {
            return (Rank1DataVisitor.FluentVisitor) super.onBytes(consumer);
        }

        @Override
        public void rank1Array(Rank1Array array) {
            arrayConsumer.accept(array);
        }

        @Override
        public void rank1Map(Rank1Map map) {
            mapConsumer.accept(map);
        }
    }
}
