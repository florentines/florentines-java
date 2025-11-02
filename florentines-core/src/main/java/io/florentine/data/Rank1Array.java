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

import static java.util.Objects.requireNonNull;

public final class Rank1Array {
    private final Rank2Array items;

    private Rank1Array(Rank2Array array) {
        this.items = array;
    }

    public static Rank1Array of(Object... args) {
        var rank2 = Rank2Array.of(args);
        rank2.forEach(new Rank2ArrayVisitor<RuntimeException>() {
            @Override
            public void rank1Array(Rank1Array array) {
                throw new IllegalArgumentException("Invalid type in Rank1Array: " + array);
            }

            @Override
            public void rank1Map(Rank1Map map) {
                throw new IllegalArgumentException("Invalid type in Rank1Array: " + map);
            }

            @Override
            public void bool(boolean value) {}
            @Override
            public void integer(long i) {}
            @Override
            public void num(double value) {}
            @Override
            public void text(String value) {}
            @Override
            public void bytes(byte[] value) {}
        });
        return new Rank1Array(rank2);
    }

    public Rank1Array add(boolean value) {
        items.add(value);
        return this;
    }

    public Rank1Array add(long value) {
        items.add(value);
        return this;
    }

    public Rank1Array add(double value) {
        items.add(value);
        return this;
    }

    public Rank1Array add(String value) {
        items.add(requireNonNull(value));
        return this;
    }

    public Rank1Array add(byte[] value) {
        items.add(value.clone());
        return this;
    }

    public <E extends Exception> void forEach(Rank1ArrayVisitor<E> visitor) throws E {
        items.forEach(new Rank2ArrayVisitor<E>() {
            @Override
            public void rank1Array(Rank1Array array) throws E {
                throw new AssertionError("unreachable");
            }

            @Override
            public void rank1Map(Rank1Map map) throws E {
                throw new AssertionError("unreachable");
            }

            @Override
            public void bool(boolean value) throws E {
                visitor.bool(value);
            }

            @Override
            public void integer(long i) throws E {
                visitor.integer(i);
            }

            @Override
            public void num(double value) throws E {
                visitor.num(value);
            }

            @Override
            public void text(String value) throws E {
                visitor.text(value);
            }

            @Override
            public void bytes(byte[] value) throws E {
                visitor.bytes(value);
            }
        });
    }

    public int size() {
        return items.size();
    }

    @Override
    public String toString() {
        return "Rank1Array" + items.items;
    }
}
