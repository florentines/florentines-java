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

public interface Rank1EntryVisitor extends Rank0EntryVisitor {
    void rank1Array(String key, Rank1Array array);
    void rank1Map(String key, Rank1Map map);

    static FluentVisitor visitor() {
        return new FluentVisitor();
    }

    class FluentVisitor extends Rank0EntryVisitor.FluentVisitor implements Rank1EntryVisitor {
        private BiConsumer<String, Rank1Array> arrayConsumer = (k, v) -> {};
        private BiConsumer<String, Rank1Map> mapConsumer = (k, v) -> {};

        public Rank1EntryVisitor.FluentVisitor onArray(BiConsumer<String, Rank1Array> consumer) {
            this.arrayConsumer = requireNonNull(consumer);
            return this;
        }

        public Rank1EntryVisitor.FluentVisitor onMap(BiConsumer<String, Rank1Map> consumer) {
            this.mapConsumer = requireNonNull(consumer);
            return this;
        }

        @Override
        public Rank1EntryVisitor.FluentVisitor onBoolean(BiConsumer<String, Boolean> consumer) {
            return (Rank1EntryVisitor.FluentVisitor) super.onBoolean(consumer);
        }

        @Override
        public Rank1EntryVisitor.FluentVisitor onLong(BiConsumer<String, Long> consumer) {
            return (Rank1EntryVisitor.FluentVisitor) super.onLong(consumer);
        }

        @Override
        public Rank1EntryVisitor.FluentVisitor onString(BiConsumer<String, String> consumer) {
            return (Rank1EntryVisitor.FluentVisitor) super.onString(consumer);
        }

        @Override
        public Rank1EntryVisitor.FluentVisitor onBytes(BiConsumer<String, byte[]> consumer) {
            return (Rank1EntryVisitor.FluentVisitor) super.onBytes(consumer);
        }

        @Override
        public void rank1Array(String key, Rank1Array array) {
            arrayConsumer.accept(key, array);
        }

        @Override
        public void rank1Map(String key, Rank1Map map) {
            mapConsumer.accept(key, map);
        }
    }
}
