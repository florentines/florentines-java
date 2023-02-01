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

package io.florentine;

import io.florentine.crypto.KEMState;
import io.florentine.crypto.Utils;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class Florentine {

    private final List<Packet> packets;

    private Florentine(List<Packet> packets) {
        this.packets = packets;
    }

    private static Optional<Florentine> parse(List<Packet> packets) {
        int lastType = 0;
        var mandatoryPackets = EnumSet.of(PacketType.HEADER, PacketType.TAG);

        for (var packet : packets) {
            if (packet.packetType().value < lastType) {
                return Optional.empty();
            }
            if (packet.packetType().value == lastType && !packet.packetType().isMultiValued()) {
                return Optional.empty();
            }
            mandatoryPackets.remove(packet.packetType());
            lastType = packet.packetType().value;
        }

        if (!mandatoryPackets.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(new Florentine(packets));
    }

    public Florentine restrict(String caveat) {
        return this;
    }

    public static final class Builder {
        private final List<Packet> packets = new ArrayList<>();
        private final Map<String, String> headers = new TreeMap<>();

        public Builder compressionAlgorithm(Compression compression) {
            headers.put("zip", compression.identifier());
            return this;
        }

        public Builder contentType(String contentType) {
            if (contentType.startsWith("application/")) {
                contentType = contentType.substring("application/".length());
            }
            headers.put("cty", contentType);
            return this;
        }

        public Builder criticalHeaders(String... headerNames) {
            // FIXME...
            headers.put("crit", List.of(headerNames).toString());
            return this;
        }

        public Builder compressedPublicContent(byte[] content) {
            packets.add(new Packet(PacketType.PUBLIC_PAYLOAD, content, PacketFlag.COMPRESSED));
            return this;
        }

        public Builder compressedPublicContent(String content) {
            return compressedPublicContent(content.getBytes(UTF_8));
        }

        public Builder publicContent(byte[] content) {
            packets.add(new Packet(PacketType.PUBLIC_PAYLOAD, content));
            return this;
        }

        public Builder publicContent(String content) {
            return publicContent(content.getBytes(UTF_8));
        }

        public Builder compressedSecretContent(byte[] content) {
            packets.add(new Packet(PacketType.SECRET_PAYLOAD, content, PacketFlag.COMPRESSED));
            return this;
        }

        public Builder compressedSecretContent(String content) {
            return compressedSecretContent(content.getBytes(UTF_8));
        }

        public Builder secretContent(byte[] content) {
            packets.add(new Packet(PacketType.SECRET_PAYLOAD, content));
            return this;
        }

        public Builder secretContent(String content) {
            return secretContent(content.getBytes(UTF_8));
        }

        public Florentine buildAuthenticated(AlgorithmSuite algorithm, KeyPair senderKeys,
                                             List<PublicKey> recipients, byte[] context) {
            if (!algorithm.isAuthenticated()) {
                throw new IllegalArgumentException("Algorithm suite is not authenticated");
            }

            try (var kemState = algorithm.authKem.begin(senderKeys, recipients, context)) {
                return build(kemState, algorithm);
            }
        }

        public Florentine buildAnonymous(AlgorithmSuite algorithm, List<PublicKey> recipients, byte[] context) {
            if (algorithm.isAuthenticated()) {
                throw new IllegalArgumentException("Algorithm suite is authenticated");
            }

            try (var kemState = algorithm.anonKem.beginEncap(recipients, context)) {
                return build(kemState, algorithm);
            }
        }

        private Florentine build(KEMState kemState, AlgorithmSuite algorithm) {
            var baos = new ByteArrayOutputStream();
            headers.forEach((key, value) -> {
                baos.write(key.length());
                baos.writeBytes(key.getBytes(UTF_8));
                baos.write(value.length());
                baos.writeBytes(value.getBytes(UTF_8));
            });
            var header = new Packet(PacketType.HEADER, baos.toByteArray());
            packets.add(0, header);

            var compression = Compression.of(headers.get("zip")).orElse(Compression.DEFLATE);

            var demKey = kemState.key();

            var associatedData = new ArrayList<byte[]>();
            var secretPackets = new ArrayList<byte[]>();

            for (var packet : packets) {
                if (packet.isCompressed()) {
                    packet = new Packet(packet.header, compression.compress(packet.content));
                }

                if (packet.isEncrypted()) {
                    secretPackets.add(packet.content);
                    associatedData.add(new byte[] { packet.header });
                } else {
                    associatedData.add(new byte[] { packet.header });
                    associatedData.add(packet.content);
                }
            }

            var tag = algorithm.dem.encrypt(demKey, secretPackets, associatedData);
            packets.add(new Packet(PacketType.SIV, tag));
            tag = algorithm.dem.encrypt(demKey, List.of(), List.of(tag));
            packets.add(new Packet(PacketType.TAG, tag));
            Utils.destroy(demKey);

            return new Florentine(packets);
        }
    }


    private record Packet(byte header, byte[] content) {

        Packet(PacketType type, byte[] content, PacketFlag... flags) {
            this(PacketFlag.toHeader(type, flags), content);
        }

        PacketType packetType() {
            return PacketType.fromHeader(header);
        }

        EnumSet<PacketFlag> flags() {
            return PacketFlag.fromHeader(header);
        }

        boolean isEncrypted() {
            return packetType() == PacketType.SECRET_PAYLOAD;
        }

        boolean isCompressed() {
            return flags().contains(PacketFlag.COMPRESSED);
        }
    }

    private enum PacketType {
        HEADER(0x01, false),
        PUBLIC_PAYLOAD(0x02, true),
        SECRET_PAYLOAD(0x03, true),
        SIV(0x04, false),
        CAVEAT(0x07, true),
        TAG(0x0F, false);

        private final byte value;
        private final boolean multiValued;

        PacketType(int value, boolean multiValued) {
            this.value = (byte) value;
            this.multiValued = multiValued;
        }

        public boolean isMultiValued() {
            return multiValued;
        }

        static PacketType fromHeader(byte header) {
            int value = header & 0x0F;
            for (var candidate : values()) {
                if (candidate.value == value) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException("Unknown packet type: " + value);
        }

    }

    private enum PacketFlag {
        COMPRESSED(1 << 0),
        RESERVED1(1 << 1),
        RESERVED2(1 << 2),
        RESERVED3(1 << 3)
        ;
        private final int bitMask;
        PacketFlag(int bitMask) {
            this.bitMask = bitMask;
        }

        static EnumSet<PacketFlag> fromHeader(byte header) {
            int flags = (header & 0xF0) >>> 4;
            var set = EnumSet.noneOf(PacketFlag.class);
            for (var flag : values()) {
                if ((flags & flag.bitMask) != 0) {
                    set.add(flag);
                }
            }
            return set;
        }

        static byte toHeader(PacketType type, PacketFlag... flags) {
            int flagNibble = Arrays.stream(flags)
                    .filter(Objects::nonNull)
                    .mapToInt(flag -> flag.bitMask)
                    .reduce((x, y) -> x | y).orElse(0);
            return (byte) (type.value | (flagNibble << 4));
        }
    }
}
