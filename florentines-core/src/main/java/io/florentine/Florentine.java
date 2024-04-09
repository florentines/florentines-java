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
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

import org.msgpack.value.ImmutableValue;

import io.florentine.crypto.CryptoSuite;
import io.florentine.crypto.DEM;
import io.florentine.crypto.DestroyableSecretKey;

public final class Florentine {
    /*
     * Structure of a Florentine on the wire:
     * <preamble> - KEM-specific
     * <header> - MsgPack map format, string keys
     * <payload>+ - one or more encrypted payload sections
     * <tag> - the payload tag (16 bytes)
     * <caveat>* - MsgPack map format (0 or more)
     * <caveat key> - (64 bytes)
     *
     * Each packet has a length field (encoded as a varint), a single-byte header, and the payload.
     */

    private final List<Packet> packets;
    private final DEM dem;

    private DestroyableSecretKey caveatKey;

    private Florentine(Builder builder) {
        this.dem = DEM.CC20HS512;
        var packets = List.<Packet>of(); // TODO


        // Compress

        // Encrypt
        try (var key = dem.importKey(new byte[32])) {
            var tagAndKey = dem.encrypt(key, packets);
            caveatKey = tagAndKey.caveatKey();
            var tagPacket = new Packet(PacketType.TAG, tagAndKey.tag(), PacketFlags.CRITICAL);
            append(tagPacket);
        }

        this.packets = List.copyOf(packets);
    }

    private void append(Packet packet) {
        assert packet.type() != PacketType.CAVEAT_KEY;
        var tag = dem.encrypt(caveatKey, List.of(packet));
        caveatKey.destroy();
        caveatKey = tag.caveatKey();
    }

    public static Builder builder(CryptoSuite cryptoSuite) {
        return new Builder();
    }

    public static class Builder {
        final Map<String, ImmutableValue> headers = new TreeMap<>();

        public Builder header(String key, String value) {
            headers.put(key, newString(value));
            return this;
        }

        public Builder header(String key, boolean value) {
            headers.put(key, newBoolean(value));
            return this;
        }

        public Florentine build() {
            return new Florentine(this);
        }
    }

    record Packet(PacketType type, byte[] content, PacketFlags... flags) implements DEM.Part {

        @Override
        public boolean isEncrypted() {
            return Stream.of(flags).anyMatch(flag -> flag == PacketFlags.ENCRYPTED);
        }

        @Override
        public byte[] header() {
            // header is 4-bit type followed by 4 flag bits
            byte header = type.nibble;
            for (var flag : flags) {
                header |= (byte) (1 << flag.bitPosition);
            }
            return new byte[] { header };
        }

        int writeTo(DataOutputStream out) throws IOException {
            writeVarInt(out, content.length + 1);
            out.writeByte(header()[0]);
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
        TAG(0x50),
        CAVEAT(0xa0),
        CAVEAT_KEY(0xf0);

        final byte nibble;

        PacketType(int nibble) {
            this.nibble = (byte) nibble;
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
