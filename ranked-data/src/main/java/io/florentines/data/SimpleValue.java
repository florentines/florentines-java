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

package io.florentines.data;

import static java.util.Objects.*;

public abstract class SimpleValue<T> {

    final T value;

    SimpleValue(T value) {
        this.value = requireNonNull(value, "value");
    }

    public T value() {
        return value;
    }

    public abstract  <S> S accept(Visitor<S> visitor);

    public static BoolValue boolValue(boolean value) {
        return value ? BoolValue.TRUE : BoolValue.FALSE;
    }

    public static LongValue longValue(long value) {
        return new LongValue(value);
    }

    public static TextValue textValue(String value) {
        return new TextValue(value);
    }

    public static ByteArray byteArray(byte[] value) {
        return new ByteArray(value);
    }

    public static final class TextValue extends SimpleValue<String> {
        public TextValue(String value) { super(value); }

        @Override
        public <S> S accept(Visitor<S> visitor) {
            return visitor.onTextValue(value);
        }
    }

    public static final class BoolValue extends SimpleValue<Boolean> {
        public static final BoolValue TRUE = new BoolValue(true);
        public static final BoolValue FALSE = new BoolValue(false);
        private BoolValue(Boolean value) { super(value); }

        @Override
        public <S> S accept(Visitor<S> visitor) {
            return visitor.onBoolValue(value);
        }
    }

    public static final class LongValue extends SimpleValue<Long> {
        public LongValue(Long value) {
            super(value);
        }

        @Override
        public <S> S accept(Visitor<S> visitor) {
            return visitor.onLongValue(value);
        }
    }

    public static final class ByteArray extends SimpleValue<byte[]> {
        public ByteArray(byte[] value) {
            super(value.clone());
        }

        @Override
        public <S> S accept(Visitor<S> visitor) {
            return visitor.onByteArray(value.clone());
        }

        @Override
        public byte[] value() {
            return value.clone();
        }
    }


    public interface Visitor<T> {
        T onBoolValue(boolean value);
        T onLongValue(long value);
        T onTextValue(String value);
        T onByteArray(byte[] value);
    }
}
