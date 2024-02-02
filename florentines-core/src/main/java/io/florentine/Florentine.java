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

import static org.msgpack.value.ValueFactory.newBoolean;
import static org.msgpack.value.ValueFactory.newString;

import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;

import org.msgpack.value.ImmutableValue;

public final class Florentine {
    /*
     * Structure of a Florentine on the wire:
     * <preamble> - KEM-specific
     * <header> - MsgPack map format, string keys
     * <payload>+ - one or more encrypted payload sections
     * <siv> - the synthetic IV
     * <caveat>* - MsgPack map format (0 or more)
     * <tag>
     *
     * Each packet has a length field (encoded as a varint), a single-byte header, and the payload.
     */

    private Florentine(Builder builder) {

    }

    public static class Builder {
        final Map<String, ImmutableValue> headers = new TreeMap<>();

        public Builder header(String key, String value) {
            headers.put(key, newString(value).asStringValue());
            return this;
        }

        public Builder header(String key, boolean value) {
            headers.put(key, newBoolean(value));
            return this;
        }


    }

    record Packet(PacketType type, byte[] content, PacketFlags... flags) {

        int writeTo(DataOutputStream out) throws IOException {
            writeVarInt(out,content.length + 1);
            // header is 4-bit type followed by 4 flag bits
            byte header = type.nybble;
            for (var flag : flags) {
                header |= (byte) (1 << flag.bitPosition);
            }
            out.writeByte(header);
            out.write(content);

            return content.length + 2;
        }
    }

    enum PacketFlags {
        COMPRESSED(0),
        ENCRYPTED(1),
        CRITICAL(2),
        RESERVED(3);

        final int bitPosition;

        PacketFlags(int bitPosition) {
            this.bitPosition = bitPosition;
        }
    }

    enum PacketType {
        PREAMBLE(0x00),
        HEADER(0x10),
        PAYLOAD(0x20),
        SIV(0x50),
        CAVEAT(0xa0),
        TAG(0xf0);

        final byte nybble;

        PacketType(int nybble) {
            this.nybble = (byte) nybble;
        }
    }

    static void writeVarInt(DataOutputStream out, long value) throws IOException {
        while (value > 0) {
            int b = (int) (value & 0x7F);
            if (value > 0x7F) {
                b |= 0x80;
            }
            out.write(b);
            value >>>= 7;
        }
    }
}
