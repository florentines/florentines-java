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

import static java.util.Objects.requireNonNull;

import java.util.EnumSet;
import java.util.List;

abstract class Record implements DEM.Record {
    enum Type {
        KEM_DATA(0),
        HEADER(1),
        PAYLOAD(2),
        TAG(10),
        CAVEAT(11),
        END(15);

        final int value;
        Type(int value) {
            assert value >= 0 && value < 16;
            this.value = value;
        }
    }

    enum Flag {
        /** Indicates that the content of the record are compressed. */
        COMPRESSED,
        /**
         * Indicates that the record is critical to secure processing of the content. If the application doesn't
         * understand this packet type or the content of the record then it should reject the entire Florentine.
         */
        CRITICAL
    }

    private final Type type;
    private final EnumSet<Flag> flags;
    private final byte[] headerByte;

    Record(Type type, Flag... flags) {
        this.type = requireNonNull(type, "type");
        var flagSet = EnumSet.noneOf(Flag.class);
        flagSet.addAll(List.of(flags));
        this.flags = flagSet;

        byte f = 0;
        for (var flag : flags) {
            f |= (byte) (1 << flag.ordinal());
        }
        headerByte = new byte[] { (byte) ((type.value << 4) | f) };
    }

    Type type() {
        return type;
    }

    EnumSet<Flag> flags() {
        return flags;
    }

    @Override
    public byte[] secretContent() {
        return Utils.emptyBytes();
    }

    @Override
    public byte[] publicContent() {
        return Utils.emptyBytes();
    }

    @Override
    public final byte[] assocData() {
        return headerByte;
    }

    public boolean isCritical() {
        return flags.contains(Flag.CRITICAL);
    }
}
