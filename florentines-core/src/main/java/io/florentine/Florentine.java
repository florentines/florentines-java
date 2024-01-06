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

import static java.nio.charset.StandardCharsets.*;
import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonWriter;

import io.florentine.caveat.Caveat;
import io.florentine.crypto.AuthKEM;
import io.florentine.crypto.DEM;

public final class Florentine {

    private final byte[] kemState;
    private final Headers headers;
    private final byte[] siv;
    private byte[] tag;

    private final List<Packet> packets;

    private Florentine(List<Packet> packets) {
        this.packets = packets;

        this.kemState = findPacket(PacketType.KEM_DATA).orElseThrow();
        this.headers = findPacket(PacketType.HEADER).flatMap(Headers::parse).orElseThrow();
        this.siv = findPacket(PacketType.SIV).orElseThrow();
        this.tag = findPacket(PacketType.TAG).orElseThrow();
    }

    public static Builder create(AlgorithmSuite algorithm, KeyPair senderKeys, PublicKey... recipients) {
        return new Builder(algorithm, algorithm.kem.begin(algorithm.dem, senderKeys, List.of(recipients)));
    }

    @Override
    public String toString() {
        try (var baos = new ByteArrayOutputStream()) {
            writeTo(baos);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void writeTo(OutputStream out) throws IOException {
        for (var packet : packets) {
            packet.writeTo(out);
        }
    }

    public Florentine restrict(Caveat caveat) {
        var demAlg = headers.header("dem").orElse("XS20SIV-HS512");
        var dem = DEM.lookup(demAlg).orElseThrow(() -> new IllegalArgumentException("Unknown DEM algorithm"));

        try (var demState = dem.beginEncapsulation(dem.importKey(tag))) {
            var json =
                    JsonWriter.string(JsonObject.builder().object(caveat.predicate(), caveat.value().asMap().orElseThrow()).done());
            var packet = new Packet(PacketType.CAVEAT, json.getBytes(UTF_8),
                    caveat.critical() ? new PacketFlag[] { PacketFlag.CRITICAL } : new PacketFlag[0]);
            var newTag = demState.withContext(new byte[] { packet.header }, packet.content ).done().key().getEncoded();

            Arrays.fill(this.tag, (byte) 0);
            this.tag = newTag;
            var oldTag = packets.remove(packets.size() - 1);
            if (oldTag.type() != PacketType.TAG) {
                throw new IllegalStateException("Missing tag packet");
            }
            packets.add(packet);
            packets.add(new Packet(PacketType.TAG, newTag));
        }

        return this;
    }

    public Optional<Void> decrypt(AlgorithmSuite algorithm, KeyPair localKeys, PublicKey... possibleSenderKeys) {
        var headerHash = algorithm.dem.hash(findPacket(PacketType.HEADER).orElseThrow());
        var kemState = algorithm.kem.begin(algorithm.dem, localKeys, List.of(possibleSenderKeys));

        var siv = findPacket(PacketType.SIV).orElseThrow();
        var kemData = findPacket(PacketType.KEM_DATA).orElseThrow();
        var decapsulationStateOpt = kemState.decapsulate(kemData, siv, headerHash);
        if (decapsulationStateOpt.isEmpty()) {
            return Optional.empty();
        }

        var decapsulationState = decapsulationStateOpt.get();
        var demKey = decapsulationState.demKey();
        var compression = headers.compression();

        var contents = new ArrayList<byte[]>();

        var headerWrapper = new byte[1];
        try (var decapsulator = algorithm.dem.beginDecapsulation(demKey, siv)) {
            for (var it = packets.listIterator(); it.hasNext(); ) {
                var packet = it.next();
                headerWrapper[0] = packet.header;
                if (packet.isEncrypted()) {
                    decapsulator.withContext(headerWrapper).decapsulate(packet.content);
                } else if (packet.isAuthenticated()) {
                    decapsulator.withContext(headerWrapper, packet.content);
                }

                if (packet.isCompressed()) {
                    packet = new Packet(packet.header(), compression.decompress(packet.content()));
                    it.set(packet);
                }

                if (packet.type() == PacketType.CONTENT) {
                    contents.add(packet.content());
                }
            }

            return decapsulator.verify().map(chainingKey -> {
                // TODO: verify caveats...
//                return new CaveatVerifier(decapsulationState.replyState(), header, contents, List.of());
                return null;
            });
        }
    }

    private Optional<byte[]> findPacket(PacketType type) {
        return packets.stream()
                .filter(packet -> packet.type().equals(type))
                .findFirst()
                .map(Packet::content);
    }

    public static Optional<Florentine> fromString(String encoded) {
        try {
            return readFrom(Base64.getUrlDecoder().wrap(new ByteArrayInputStream(encoded.getBytes())));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    public static Optional<Florentine> readFrom(InputStream in) throws IOException {
        var packets = new ArrayList<Packet>();
        var packet = Packet.readFrom(in);
        PacketType lastType = null;
        while (packet.isPresent()) {
            var type = packet.get().type();
            if (lastType != null) {
                if (type.compareTo(lastType) < 0) {
                    throw new IOException("Illegal packet order");
                } else if (type.equals(lastType) && !type.multiValued()) {
                    throw new IOException("Illegal duplicate packet: " + type);
                } else if (packet.get().isCritical() && type.isUnknown()) {
                    throw new IOException("Unknown critical packet: " + type);
                }
            }
            lastType = type;
            packets.add(packet.get());
            packet = Packet.readFrom(in);
        }
        System.out.println("Read packets:");
        packets.forEach(System.out::println);
        return Optional.of(new Florentine(packets));
    }

    public static final class Builder {
        private final AlgorithmSuite algorithm;
        private final AuthKEM.State kemState;
        private final List<Packet> packets = new ArrayList<>();
        /*
         * A header has a string key and the value is one of:
         *  - a string
         *  - a 64-bit signed integer
         *  - a double-precision floating-point number
         *  - a boolean (true/false)
         *  - a list of one of the above types
         *  - a binary byte array
         */
        private final Map<String, Object> headers = new TreeMap<>();

        Builder(AlgorithmSuite algorithmSuite, AuthKEM.State state) {
            this.algorithm = algorithmSuite;
            this.kemState = state;
        }

        public Builder header(String key, String value) {
            headers.put(requireNonNull(key, "key"), requireNonNull(value, "value"));
            return this;
        }

        public Builder header(String key, long value) {
            headers.put(requireNonNull(key, "key"), value);
            return this;
        }

        public Builder header(String key, double value) {
            if (Double.isNaN(value)) {
                throw new IllegalArgumentException("NaN not allowed!");
            }
            headers.put(requireNonNull(key, "key"), value);
            return this;
        }

        public Builder header(String key, byte[] value) {
            headers.put(requireNonNull(key, "key"), requireNonNull(value, "value").clone());
            return this;
        }

        public Builder header(String key, boolean value) {
            headers.put(requireNonNull(key), value);
            return this;
        }

        public Builder header(String key, List<Object> value) {
            List<Object> values = List.copyOf(value);
            if (!values.stream().allMatch(Builder::isPrimitiveType)) {
                throw new IllegalArgumentException("Invalid type in list");
            }
            headers.put(key, values);
            return this;
        }

        private static boolean isPrimitiveType(Object object) {
            return object instanceof String || object instanceof Long || object instanceof Integer ||
                    object instanceof Short || object instanceof Byte || object instanceof Double ||
                    object instanceof Float || object instanceof Boolean || object instanceof byte[];
        }

        public Builder compressionAlgorithm(Compression compression) {
            return header("zip", compression.identifier());
        }

        public Builder contentType(String contentType) {
            if (contentType.startsWith("application/")) {
                contentType = contentType.substring("application/".length());
            }
            return header("cty", contentType);
        }

        public Builder criticalHeaders(String... headerNames) {
            return header("crit", List.of(headerNames));
        }

        public Builder compressedPublicContent(byte[] content) {
            packets.add(new Packet(PacketType.CONTENT, content, PacketFlag.COMPRESSED));
            return this;
        }

        public Builder compressedPublicContent(String content) {
            return compressedPublicContent(content.getBytes(UTF_8));
        }

        public Builder publicContent(byte[] content) {
            packets.add(new Packet(PacketType.CONTENT, content));
            return this;
        }

        public Builder publicContent(String content) {
            return publicContent(content.getBytes(UTF_8));
        }

        public Builder compressedSecretContent(byte[] content) {
            packets.add(new Packet(PacketType.CONTENT, content, PacketFlag.ENCRYPTED, PacketFlag.COMPRESSED));
            return this;
        }

        public Builder compressedSecretContent(String content) {
            return compressedSecretContent(content.getBytes(UTF_8));
        }

        public Builder secretContent(byte[] content) {
            packets.add(new Packet(PacketType.CONTENT, content, PacketFlag.ENCRYPTED));
            return this;
        }

        public Builder secretContent(String content) {
            return secretContent(content.getBytes(UTF_8));
        }

        public Florentine build() {
            headers.put("dem", algorithm.dem.getAlgorithmIdentifier());
            System.out.println("Headers: " + headers);
            var headerData = JsonWriter.string().object(headers).done().getBytes(UTF_8);
            var header = new Packet(PacketType.HEADER, headerData);
            packets.add(0, header);

            var demKey = kemState.key();
            var compression = Compression.of((String) headers.get("zip")).orElse(Compression.DEFLATE);

            try (var demState = algorithm.dem.beginEncapsulation(demKey)) {
                var headerWrapper = new byte[1];
                for (var packet : packets) {
                    headerWrapper[0] = packet.header;
                    if (packet.isCompressed()) {
                        var compressed = compression.compress(packet.content);
                        Arrays.fill(packet.content, (byte) 0);
                        packet = new Packet(packet.header, compressed);
                    }

                    if (packet.isEncrypted()) {
                        demState.withContext(headerWrapper).encapsulate(packet.content);
                    } else {
                        demState.withContext(headerWrapper, packet.content);
                    }
                }

                var keyAndTag = demState.done();
                packets.add(0, new Packet(PacketType.SIV, keyAndTag.tag()));
                packets.add(new Packet(PacketType.TAG, keyAndTag.key().getEncoded()));

                var headerHash = algorithm.dem.hash(headerData);
                var keyEncapsulation = kemState.encapsulate(keyAndTag.tag(), headerHash);
                packets.add(2, new Packet(PacketType.KEM_DATA, keyEncapsulation.encapsulatedKey()));

                System.out.println("Encrypted packets:");
                packets.forEach(System.out::println);

                return new Florentine(packets);
            }
        }
    }


    record Packet(byte header, byte[] content) {

        /**
         * Florentines currently only support varints of 1..3 bytes in size, giving a maximum size of 2^(7*3) = 2^21 =
         * 2,097,152 (exactly 2MiB). This limit should be sufficient for the intended use-cases given that Florentine
         * decryption doesn't support streaming.
         */
        static final int MAX_SIZE = 2097151; // 2MiB - 1 byte

        Packet(PacketType type, byte[] content, PacketFlag... flags) {
            this(PacketFlag.toHeader(type, flags), content);
        }

        PacketType type() {
            return PacketType.fromHeader(header);
        }

        EnumSet<PacketFlag> flags() {
            return PacketFlag.fromHeader(header);
        }

        boolean isEncrypted() {
            return flags().contains(PacketFlag.ENCRYPTED);
        }

        boolean isCompressed() {
            return flags().contains(PacketFlag.COMPRESSED);
        }

        boolean isCritical() {
            return flags().contains(PacketFlag.CRITICAL);
        }

        boolean isAuthenticated() {
            return type() != PacketType.SIV && type() != PacketType.KEM_DATA && type() != PacketType.TAG;
        }

        void writeTo(OutputStream out) throws IOException {
            out.write(header);
            Utils.writeVarInt(out, content.length);
            out.write(content, 0, content.length);
        }

        static Optional<Packet> readFrom(InputStream in) throws IOException {
            int header = in.read();
            if (header == -1) { return Optional.empty(); }
            var len = Utils.readVarInt(in);
            var data = in.readNBytes(len);
            if (data.length < len) {
                throw new EOFException();
            }
            return Optional.of(new Packet((byte) header, data));
        }

        @Override
        public String toString() {
            return "Packet:\n  type=" + type() + "\n  flags=" + flags() + "\n  content=\n" + Utils.hexDump(content) + "\nend";
        }
    }

    record PacketType(String name, int order, boolean multiValued) implements Comparable<PacketType> {
        static final PacketType SIV = new PacketType("SIV", 0x0, false);
        static final PacketType HEADER = new PacketType("HEADER", 0x1, false);
        static final PacketType KEM_DATA = new PacketType("KEM_DATA", 0x2, false);
        static final PacketType CONTENT = new PacketType("CONTENT", 0x3, true);
        static final PacketType CAVEAT = new PacketType("CAVEAT", 0x7, true);
        static final PacketType TAG = new PacketType("TAG", 0xF, false);

        static final PacketType[] VALUES = new PacketType[] {
                SIV, HEADER, KEM_DATA, CONTENT, CAVEAT, TAG
        };

        static PacketType[] values() {
            return VALUES;
        }

        static PacketType fromHeader(byte header) {
            int order = header & 0x0F;
            for (var candidate : values()) {
                if (order == candidate.order) {
                    return candidate;
                }
            }
            return new PacketType("UNKNOWN", order, true);
        }

        boolean isUnknown() {
            return Arrays.binarySearch(values(), this) < 0;
        }

        @Override
        public int compareTo(PacketType that) {
            return Integer.compare(this.order, that.order);
        }
    }

    private enum PacketFlag {
        /**
         * Indicates that the content is compressed using the compression algorithm specified in the header.
         */
        COMPRESSED(1 << 0),
        /**
         * Indicates that the packet content is encrypted.
         */
        ENCRYPTED(1 << 1),
        /**
         * Indicates that the packet is critical to security. By default, a Florentine processor should ignore any
         * packets that it doesn't understand. If this flag is set then it should instead reject the entire
         * Florentine if the packet type or contents are not understood.
         */
        CRITICAL(1 << 2),
        /**
         * Reserved for future use.
         */
        RESERVED(1 << 3)
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
            return (byte) (type.order | (flagNibble << 4));
        }
    }
}
