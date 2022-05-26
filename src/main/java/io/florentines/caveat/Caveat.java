/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines.caveat;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public abstract class Caveat {

    private final String key;
    final Object value;

    Caveat(String key, Object value) {
        this.key = Objects.requireNonNull(key, "key");
        this.value = Objects.requireNonNull(value, "value");
    }

    public String key() {
        return key;
    }

    public abstract Object value();

    public static StringCaveat string(String key, String value) {
        return new StringCaveat(key, value);
    }

    public static IntegerCaveat integer(String key, BigInteger value) {
        return new IntegerCaveat(key, value);
    }

    public static IntegerCaveat integer(String key, long value) {
        return integer(key, BigInteger.valueOf(value));
    }

    public static DoubleCaveat doublePrecision(String key, double value) {
        return new DoubleCaveat(key, value);
    }

    public static BinaryCaveat binary(String key, byte[] value) {
        return new BinaryCaveat(key, value);
    }

    public static ArrayCaveat array(String key, List<String> value) {
        return new ArrayCaveat(key, value);
    }

    public static MapCaveat map(String key, Map<String, String> value) {
        return new MapCaveat(key, value);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        Caveat that = (Caveat) other;
        return this.key.equals(that.key) && Objects.equals(this.value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(key, value);
    }

    @Override
    public String toString() {
        return "Caveat{key='" + key + "', value=" + value + "}";
    }

    public static final class StringCaveat extends Caveat {
        StringCaveat(String key, String value) {
            super(key, value);
        }

        @Override
        public String value() {
            return (String) value;
        }
    }

    public static final class IntegerCaveat extends Caveat {
        IntegerCaveat(String key, BigInteger value) {
            super(key, value);
        }

        @Override
        public BigInteger value() {
            return (BigInteger) value;
        }
    }

    public static final class DoubleCaveat extends Caveat {
        DoubleCaveat(String key, double value) {
            super(key, value);
        }

        @Override
        public Double value() {
            return (double) value;
        }
    }

    public static final class BinaryCaveat extends Caveat {
        BinaryCaveat(String key, byte[] value) {
            super(key, value.clone());
        }

        @Override
        public byte[] value() {
            return ((byte[]) value).clone();
        }
    }

    public static final class ArrayCaveat extends Caveat {
        ArrayCaveat(String key, List<String> value) {
            super(key, value);
        }

        @Override
        @SuppressWarnings("unchecked")
        public List<String> value() {
            return (List<String>) value;
        }
    }

    public static final class MapCaveat extends Caveat {
        MapCaveat(String key, Map<String, String> value) {
            super(key, value);
        }

        @Override
        @SuppressWarnings("unchecked")
        public Map<String, String> value() {
            return (Map<String, String>) value;
        }
    }
}
