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

import com.grack.nanojson.JsonWriter;
import io.florentine.crypto.KEM;

import java.io.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

import static io.florentine.Utils.rejectIf;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

public final class Florentine {

    private final List<Packet> packets;
    private final AlgorithmSuite algorithmSuite;
    private final KEM.State kemState;

    private Florentine(List<Packet> packets, AlgorithmSuite algorithmSuite, KEM.State state) {
        this.packets = packets;
        this.algorithmSuite = algorithmSuite;
        this.kemState = state;
    }

    public static Builder builder(AlgorithmSuite algorithm, KeyPair senderKeys, PublicKey... recipients) {
        return new Builder(algorithm, algorithm.kem.begin(algorithm.dem, senderKeys, List.of(recipients), new byte[0]));
    }

    public Optional<Builder> reply() {
        if (kemState == null) {
            return Optional.empty();
        }

        return Optional.of(new Builder(algorithmSuite, kemState));
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

    public Iterable<byte[]> decrypt(AlgorithmSuite algorithm, KeyPair localKeys, PublicKey... possibleSenderKeys) {
        var kemState = algorithm.kem.begin(algorithm.dem, localKeys, List.of(possibleSenderKeys), new byte[0]);

        byte[] siv = null;
        var messages = new ArrayList<byte[]>();
        var assocData = new ArrayList<byte[]>();

        var kemData = packets.get(0);
        Utils.checkState(kemData.packetType() == PacketType.KEM_DATA, "Missing KEM data");

        var demKey = kemState.decapsulate(siv, kemData.content()).orElseThrow();
        try (var decryptor = algorithm.dem.beginDecrypt(demKey)) {
            for (var packet : packets) {
                if (packet.packetType() == PacketType.SIV) {
                    siv = packet.content;
                } else if (packet.packetType() != PacketType.TAG) {
                    decryptor.authenticate(Utils.concat(new byte[] { packet.header }, packet.content));
                    assocData.add(new byte[]{packet.header});
                    if (packet.isEncrypted()) {
                        messages.add(packet.content);
                    } else {
                        assocData.add(packet.content);
                    }
                }
            }
        }
//        try (var decryptor = algorithm.dem.decrypt(demKey, siv, messages)) {
//            decryptor.verify(assocData).orElseThrow();
//            return messages;
//        }
        return messages;
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
        while (packet.isPresent()) {
            packets.add(packet.get());
            packet = Packet.readFrom(in);
        }

        // TODO: validate packets
        return Optional.of(new Florentine(packets, null, null));
    }

    public static final class Builder {
        private final AlgorithmSuite algorithm;
        private final KEM.State kemState;
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

        Builder(AlgorithmSuite algorithmSuite, KEM.State state) {
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
            packets.add(new Packet(PacketType.SECRET_PAYLOAD, content, PacketFlag.ENCRYPTED, PacketFlag.COMPRESSED));
            return this;
        }

        public Builder compressedSecretContent(String content) {
            return compressedSecretContent(content.getBytes(UTF_8));
        }

        public Builder secretContent(byte[] content) {
            packets.add(new Packet(PacketType.SECRET_PAYLOAD, content, PacketFlag.ENCRYPTED));
            return this;
        }

        public Builder secretContent(String content) {
            return secretContent(content.getBytes(UTF_8));
        }

        public Florentine build() {
            var headerData = JsonWriter.string().object(headers).done().getBytes(UTF_8);
            var header = new Packet(PacketType.HEADER, headerData);
            packets.add(0, header);

            var demKey = kemState.key();
            var compression = Compression.of((String) headers.get("zip")).orElse(Compression.DEFLATE);

            try (var cipher = algorithm.dem.beginEncrypt(demKey)) {
                var secretPackets = new ArrayList<byte[]>();
                for (var packet : packets) {
                    if (packet.isCompressed()) {
                        var compressed = compression.compress(packet.content);
                        Arrays.fill(packet.content, (byte) 0);
                        packet = new Packet(packet.header, compressed);
                    }

                    cipher.authenticate(Utils.concat(new byte[] { packet.header }, packet.content));
                    if (packet.isEncrypted()) {
                        secretPackets.add(packet.content);
                    }
                }

                var siv = cipher.encrypt(secretPackets.toArray(byte[][]::new));
                var tag = cipher.done();

                packets.add(0, new Packet(PacketType.SIV, siv));
                packets.add(new Packet(PacketType.TAG, tag));

                var keyEncapsulation = kemState.encapsulate(siv);
                packets.add(1, new Packet(PacketType.KEM_DATA, keyEncapsulation));
            }
            return new Florentine(packets, algorithm, kemState);
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

        PacketType packetType() {
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

        void writeTo(OutputStream out) throws IOException {
            out.write(header);
            writeVarInt(out, content.length);
            out.write(content, 0, content.length);
        }

        static Optional<Packet> readFrom(InputStream in) throws IOException {
            int header = in.read();
            if (header == -1) { return Optional.empty(); }
            var len = readVarInt(in);
            var data = in.readNBytes(len);
            if (data.length < len) {
                return Optional.empty();
            }
            return Optional.of(new Packet((byte) header, data));
        }

        static void writeVarInt(OutputStream out, int length) throws IOException {
            rejectIf(length > MAX_SIZE, "Value too large");
            rejectIf(length < 0, "Negative length");

            while (length > 0) {
                int b = length & 0x7F;
                if (length > 0x7F) {
                    b |= 0x80;
                }
                out.write(b);
                length >>>= 7;
            }
        }

        static int readVarInt(InputStream in) throws IOException {
            int value = 0, shift = 0, b;
            do {
                b = in.read();
                if (b == -1) { throw new EOFException(); }
                value += (b & 0x7F) << shift;
                shift += 7;
            } while ((b & 0x80) != 0 && shift < 28);
            if (value > MAX_SIZE || (b & 0x80) != 0) {
                throw new IOException("Varint too large");
            }
            return value;
        }
    }

    private enum PacketType {
        SIV(0x0, false),
        HEADER(0x1, false),
        KEM_DATA(0x2, false),
        PUBLIC_PAYLOAD(0x3, true),
        SECRET_PAYLOAD(0x4, true),
        CAVEAT(0x7, true),
        TAG(0xF, false);

        private final byte value;
        private final boolean multiValued;

        PacketType(int value, boolean multiValued) {
            rejectIf(value > 0xF, "Must fit in a nibble");
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
            return (byte) (type.value | (flagNibble << 4));
        }
    }

    private static int readVarInt(InputStream in) throws IOException {
        int value = 0;




        for (int i = 0; i < 3; ++i) {
            int b = in.read();
            if (b == -1) {
                break;
            }
            value = (value << 7) + (b & 0x7F);
            if ((b & 0x80) != 0) {
                break;
            }
        }
        return value;
    }
}
