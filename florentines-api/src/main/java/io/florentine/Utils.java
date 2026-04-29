/*
 * Copyright 2026 Neil Madden.
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

import java.util.Iterator;

final class Utils {
    static <T> Iterable<T> concat(Iterable<T> first, Iterable<T> second) {
        var it1 = first.iterator();
        var it2 = second.iterator();
        return () -> new Iterator<>() {
            @Override
            public boolean hasNext() {
                return it1.hasNext() || it2.hasNext();
            }

            @Override
            public T next() {
                return it1.hasNext() ? it1.next() : it2.next();
            }
        };
    }

    private Utils() {}
}
