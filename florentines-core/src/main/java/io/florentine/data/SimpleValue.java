/*
 * Copyright 2023 Neil Madden.
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

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalLong;

/**
 * Defines a simple hierarchy of value types for Florentine headers, caveats and so on. This type hierarchy
 * corresponds to <a href="https://neilmadden.blog/2023/05/31/regular-json/">Rank 1 Regular JSON</a>, and consists of
 * the following options:
 * <ul>
 *     <li>A {@link SimpleScalarValue}, which is one of:</li>
 *     <ul>
 *      <li><code>null</code>.</li>
 *      <li>The Boolean values <code>true</code> or <code>false</code>.</li>
 *      <li>A numeric value, represented as  IEEE 754 double precision floating point.</li>
 *      <li>A Unicode string.</li>
 *     </ul>
 *     <li>A map, whose keys are strings and whose values are simple scalar values.</li>
 *     <li>A list of simple scalar values.</li>
 * </ul>
 */
public sealed interface SimpleValue {

    static Optional<SimpleValue> convert(Object value) {
        // Ugly type conversion code to convert arbitrary JSON-parsed objects into simple values.
        return convertScalar(value).map(val -> (SimpleValue) val).or(() -> {
            if (value instanceof List<?> l) {
                var convertedElements = new ArrayList<SimpleScalarValue>(l.size());
                for (var element : l) {
                    var scalar = convertScalar(element);
                    if (scalar.isEmpty()) {
                        return Optional.empty();
                    }
                    convertedElements.add(scalar.get());
                }
                return Optional.of(list(convertedElements.toArray(SimpleScalarValue[]::new)));
            } else if (value instanceof Map<?, ?> m) {
                var convertedElements = new LinkedHashMap<String, SimpleScalarValue>(m.size());
                for (var entry : m.entrySet()) {
                    if (!(entry.getKey() instanceof String key)) {
                        return Optional.empty();
                    }
                    var converted = convertScalar(entry.getValue());
                    if (converted.isEmpty()) {
                        return Optional.empty();
                    }
                    convertedElements.put(key, converted.get());
                }
                return Optional.of(map(convertedElements));
            } else {
                return Optional.empty();
            }
        });
    }

    static Optional<SimpleScalarValue> convertScalar(Object value) {
        if (value == null) {
            return Optional.of(NullValue.NULL);
        } else if (value instanceof Boolean b) {
            return Optional.of(b ? BooleanValue.TRUE : BooleanValue.FALSE);
        } else if (value instanceof Number n) {
            return Optional.of(new NumericValue(n.doubleValue()));
        } else if (value instanceof String str) {
            return Optional.of(new StringValue(str));
        } else {
            return Optional.empty();
        }
    }

    static SimpleScalarValue nullValue() {
        return NullValue.NULL;
    }

    static SimpleScalarValue bool(boolean value) {
        return value ? BooleanValue.TRUE : BooleanValue.FALSE;
    }

    static SimpleScalarValue numeric(double value) {
        return new NumericValue(value);
    }

    static SimpleScalarValue string(String value) {
        return new StringValue(value);
    }

    static SimpleValue list(SimpleScalarValue... elements) {
        return new ListValue(List.of(elements));
    }

    static SimpleValue map(Map<String, ? extends SimpleScalarValue> elements) {
        return new MapValue(elements);
    }

    default boolean isNull() {
        return this instanceof NullValue;
    }

    default boolean isBoolean() {
        return this instanceof BooleanValue;
    }

    default boolean isNumeric() {
        return this instanceof NumericValue;
    }

    default boolean isString() {
        return this instanceof StringValue;
    }

    default boolean isList() {
        return this instanceof ListValue;
    }

    default boolean isMap() {
        return this instanceof MapValue;
    }

    default OptionalDouble asNumeric() {
        return this instanceof NumericValue nv ? OptionalDouble.of(nv.value) : OptionalDouble.empty();
    }

    default OptionalLong asLong() {
        return this instanceof NumericValue nv ? nv.asLong() : OptionalLong.empty();
    }

    default Optional<Instant> asInstant() {
        return asLong().stream().mapToObj(Instant::ofEpochSecond).findFirst();
    }

    default Optional<Boolean> asBoolean() {
        return this instanceof BooleanValue bv ? Optional.of(bv == BooleanValue.TRUE) : Optional.empty();
    }

    default Optional<String> asString() {
        return this instanceof StringValue sv ? Optional.of(sv.value) : Optional.empty();
    }

    default Optional<List<? extends SimpleScalarValue>> asList() {
        return this instanceof ListValue lv ? Optional.of(lv.list) : Optional.empty();
    }

    default Optional<List<String>> asListOfStrings() {
        return asList().flatMap(xs -> {
            var strings = new ArrayList<String>(xs.size());
            for (var x : xs) {
                if (!(x instanceof StringValue sv)) {
                    return Optional.empty();
                }
                strings.add(sv.value);
            }
            return Optional.of(strings);
        });
    }

    default Optional<Map<String, ? extends SimpleScalarValue>> asMap() {
        return this instanceof MapValue mv ? Optional.of(mv.map) : Optional.empty();
    }

    /**
     * A scalar value: <code>null</code>, a boolean, a double, or a string.
     */
    sealed interface SimpleScalarValue extends SimpleValue {}

    /**
     * The null value.
     */
    enum NullValue implements SimpleScalarValue { NULL }

    /**
     * A boolean value.
     */
    enum BooleanValue implements SimpleScalarValue {
        TRUE, FALSE
    }

    /**
     * A double-precision numeric value.
     *
     * @param value the value
     */
    record NumericValue(double value) implements SimpleScalarValue {
        /**
         * Attempts to convert the numeric value to a long if it can be.
         *
         * @return the value as a long if it can be exactly converted, or an empty value if it is not integral.
         */
        public OptionalLong asLong() {
            return (long) value == value ? OptionalLong.of((long) value) : OptionalLong.empty();
        }
    }

    /**
     * A string value.
     * @param value the string.
     */
    record StringValue(String value) implements SimpleScalarValue { }

    /**
     * A map from string keys to simple scalar values.
     * @param map the map.
     */
    record MapValue(Map<String, ? extends SimpleScalarValue> map) implements SimpleValue { }

    /**
     * A list of simple scalar values.
     *
     * @param list the list.
     */
    record ListValue(List<? extends SimpleScalarValue> list) implements SimpleValue { }
}
