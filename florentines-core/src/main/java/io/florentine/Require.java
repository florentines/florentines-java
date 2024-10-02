/*
 * Copyright 2024 Neil Madden.
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

package io.florentine;

import java.util.Collection;
import java.util.function.Predicate;

/**
 * Utilities for checking preconditions.
 */
final class Require {
    static <T extends Iterable<?>> T notEmpty(T items, String msg) {
        var empty = (items instanceof Collection<?> c && c.isEmpty()) || !items.iterator().hasNext();
        if (empty) {
            throw new IllegalArgumentException(msg);
        }
        return items;
    }

    static String notBlank(String item, String msg) {
        if (item == null || item.isBlank()) {
            throw new IllegalArgumentException(msg);
        }
        return item;
    }

    static void between(int value, int lowerBound, int upperBound, String msg) {
        if (value < lowerBound || value >= upperBound) {
            throw new IllegalArgumentException(msg);
        }
    }

    static <T> void matches(Predicate<? super T> pred, T it, String msg) {
        if (!pred.test(it)) {
            throw new IllegalArgumentException(msg);
        }
    }

    static <T> void all(Predicate<? super T> pred, Collection<T> it, String msg) {
        if (!it.stream().allMatch(pred)) {
            throw new IllegalArgumentException(msg);
        }
    }

    private Require() {}
}
