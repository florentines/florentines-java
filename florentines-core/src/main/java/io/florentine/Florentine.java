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

import static io.florentine.Florentine.PacketType.HEADER;
import static io.florentine.Florentine.PacketType.PAYLOAD;
import static java.util.Objects.requireNonNull;
import static org.msgpack.value.ValueFactory.newBoolean;
import static org.msgpack.value.ValueFactory.newMap;
import static org.msgpack.value.ValueFactory.newString;

import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.msgpack.core.MessagePack;
import org.msgpack.value.ImmutableStringValue;
import org.msgpack.value.ImmutableValue;

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
    private final AuthKem kem;
    private final Compression compression;

    private DestroyableSecretKey caveatKey;

    private Florentine(Builder builder) {
        this.compression = builder.compression;
        this.dem = builder.localParty.getCryptoSuite().dem();
        this.kem = builder.localParty.getCryptoSuite().kem();

        this.packets = builder.packets;

        // Encrypt
        var kemState = kem.begin(null, null); // TODO
        try (var key = kemState.key()) {
            var tagAndKey = dem.encrypt(key, packets);
            this.caveatKey = tagAndKey.caveatKey();
            var tagPacket = new Packet(PacketType.TAG, tagAndKey.tag(), PacketFlags.CRITICAL);
            append(tagPacket);
        }
    }

    private void append(Packet packet) {
        assert packet.type() != PacketType.CAVEAT_KEY;
        var tag = dem.encrypt(caveatKey, List.of(packet));
        caveatKey.destroy();
        caveatKey = tag.caveatKey();
        packets.add(packet);
    }

    public static Builder from(LocalParty localParty) {
        return new Builder(localParty);
    }

    public static class Builder {
        // Only 1 compression algorithm supported for now, so hard-code it
        final Compression compression = Compression.DEFLATE;
        final LocalParty localParty;
        final Map<ImmutableStringValue, ImmutableValue> headers = new LinkedHashMap<>();
        final List<Packet> packets = new ArrayList<>();
        final Set<RemoteParty> remoteParties = new LinkedHashSet<>();
        String applicationLabel;

        Builder(LocalParty localParty) {
            this.localParty = requireNonNull(localParty);
        }

        public Builder applicationLabel(String label) {
            this.applicationLabel = requireNonNull(applicationLabel);
            return this;
        }

        public Builder to(RemoteParty... remoteParties) {
            return to(List.of(remoteParties));
        }

        public Builder to(Collection<? extends RemoteParty> remoteParties) {
            this.remoteParties.addAll(remoteParties);
            return this;
        }

        public Builder header(String key, String value) {
            headers.put(newString(key), newString(value));
            return this;
        }

        public Builder header(String key, boolean value) {
            headers.put(newString(key), newBoolean(value));
            return this;
        }

        public Builder contentType(String contentType) {
            return header("cty", contentType);
        }

        public Builder publicPayload(byte[] payload, PacketFlags... options) {
            return payload(payload, false, options);
        }

        public Builder secretPayload(byte[] payload, PacketFlags... options) {
            return payload(payload, true, options);
        }

        private Builder payload(byte[] payload, boolean encrypted, PacketFlags... options) {
            var flags = EnumSet.noneOf(PacketFlags.class);
            flags.addAll(List.of(options));
            if (flags.contains(PacketFlags.RESERVED)) {
                throw new IllegalArgumentException("invalid flag");
            }
            if (encrypted) {
                flags.add(PacketFlags.ENCRYPTED);
            } else if (flags.contains(PacketFlags.ENCRYPTED)) {
                throw new IllegalArgumentException("Cannot encrypt public payload!");
            }
            if (flags.contains(PacketFlags.COMPRESSED)) {
                payload = compression.compress(payload);
            }

            packets.add(new Packet(PAYLOAD, payload, flags));
            return this;
        }

        public Florentine build() {
            var compiledHeaders = newMap(headers);
            try (var packer = MessagePack.newDefaultBufferPacker()) {
                compiledHeaders.writeTo(packer);
                var headerPacket = new Packet(HEADER, packer.toMessageBuffer().array());
                packets.add(0, headerPacket);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return new Florentine(this);
        }
    }

    record Packet(PacketType type, byte[] content, EnumSet<PacketFlags> flags) implements DEM.Part {

        Packet(PacketType type, byte[] content, PacketFlags... flags) {
            this(type, content, setOf(flags));
        }

        private static EnumSet<PacketFlags> setOf(PacketFlags[] flags) {
            var result = EnumSet.noneOf(PacketFlags.class);
            result.addAll(List.of(flags));
            return result;
        }

        @Override
        public boolean isEncrypted() {
            return flags.contains(PacketFlags.ENCRYPTED);
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

    public enum PacketFlags {
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
