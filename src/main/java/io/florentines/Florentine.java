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

package io.florentines;

import static io.florentines.Utils.hex;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.grack.nanojson.JsonBuilder;
import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import com.grack.nanojson.JsonWriter;


public final class Florentine<KeyType, State> {

    private final Algorithm<KeyType, State> algorithm;
    private final byte[] preamble;
    private final List<Packet> packets;
    private final byte[] siv;
    private State state;

    private byte[] tag;

    private Florentine(Algorithm<KeyType, State> algorithm, byte[] preamble, List<Packet> packets, byte[] siv,
            State state,
            DestroyableSecretKey caveatKey) {
        this.algorithm = algorithm;
        this.preamble = preamble;
        this.packets = packets;
        this.siv = siv;
        this.state = state;
        this.tag = caveatKey.getEncoded();
    }

    public static <T, S> Builder<T, S> builder(Algorithm<T, S> algorithm, FlorentineSecretKey<T> senderKeys,
            FlorentinePublicKey... recipients) {
        var state = algorithm.kem.begin(senderKeys, recipients);
        return new Builder<>(algorithm, state);
    }

    public Florentine<KeyType, State> copy() {
        return new Florentine<>(algorithm, preamble, List.copyOf(packets), siv.clone(), state,
                new DestroyableSecretKey("HmacSHA256", tag));
    }

    public Florentine<KeyType, State> restrict(JsonObject caveat) {
        var caveatBytes = JsonWriter.string(caveat).getBytes(UTF_8);
        packets.add(new Packet(PacketType.FIRST_PARTY_CAVEAT, (byte) 0, caveatBytes));

        var key = algorithm.dem.importKey(this.tag);
        try {
            var newTag = algorithm.dem.beginEncryption(key).authenticate(caveatBytes).done().getSecond();
            Arrays.fill(this.tag, (byte) 0);
            this.tag = newTag.getEncoded();
        } finally {
            key.destroy();
        }

        return this;
    }

    public Builder<KeyType, State> reply() {
        // TODO: should in-reply-to header be salted/truncated?
        return new Builder<>(algorithm, state).header("irt", Base64url.encode(siv));
    }

    public void writeTo(OutputStream outputStream) throws IOException {
        var out = new DataOutputStream(outputStream);
        try {
            out.writeShort(preamble.length);
            out.write(preamble);
            out.write(siv);

            for (var packet : packets) {
                out.write(packet.getPacketHeader());
                out.writeShort(packet.data.length);
                out.write(packet.data);
            }

            out.write((byte) PacketType.TAG.ordinal());
            out.writeShort(tag.length);
            out.write(tag);
        } finally {
            out.flush();
        }
    }

    public static <K, S> Florentine<K, S> readFrom(Algorithm<K, S> algorithm, InputStream inputStream) throws IOException {
        var in = new DataInputStream(inputStream);
        var preambleLength = in.readUnsignedShort();
        var preamble = in.readNBytes(preambleLength);
        var siv = in.readNBytes(16);

        Packet packet = null;
        var packets = new ArrayList<Packet>();
        do {
            if (packet != null) {
                packets.add(packet);
            }
            byte header = in.readByte();
            var length = in.readUnsignedShort();
            var data = in.readNBytes(length);

            packet = new Packet(header, data);
        } while (packet.type != PacketType.TAG);

        var caveatKey = algorithm.dem.importKey(packet.data);
        return new Florentine<>(algorithm, preamble, packets, siv, null, caveatKey);
    }

    @Override
    public String toString() {
        try (var baos = new ByteArrayOutputStream()) {
            writeTo(baos);
            return Base64url.encode(baos.toByteArray());
        } catch (IOException e) {
            throw new AssertionError("Unexpected IOException serializing Florentine", e);
        }
    }

    public static <K, S> Optional<Florentine<K, S>> fromString(Algorithm<K, S> algorithm, String stringForm) {
        try (var in = new ByteArrayInputStream(Base64url.decode(stringForm))) {
            return Optional.of(readFrom(algorithm, in));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    public Optional<List<byte[]>> decrypt(FlorentineSecretKey<KeyType> recipientKey,
            FlorentinePublicKey... expectedSenders) {
        var state = algorithm.kem.begin(recipientKey, expectedSenders);
        return algorithm.kem.authDecap(state, preamble, siv)
                .map(stateAndDemKey -> {
                    this.state = stateAndDemKey.getFirst();
                    return stateAndDemKey.getSecond();
                })
                .flatMap(this::decrypt)
                .flatMap(this::decompressAndVerifyCaveats);
    }

    public Optional<List<byte[]>> decryptReply(Florentine<KeyType, State> originalMessage) {
        if (!getHeader().has("irt")) {
            return Optional.empty();
        }
        var inReplyTo = Base64url.decode(getHeader().getString("irt"));
        if (!MessageDigest.isEqual(originalMessage.siv, inReplyTo)) {
            return Optional.empty();
        }
        var state = originalMessage.state;
        if (state == null) {
            return Optional.empty();
        }
        return algorithm.kem.authDecap(state, preamble, siv)
                .map(stateAndDemKey -> {
                    this.state = stateAndDemKey.getFirst();
                    return stateAndDemKey.getSecond();
                })
                .flatMap(this::decrypt)
                .flatMap(this::decompressAndVerifyCaveats);
    }

    private Optional<DestroyableSecretKey> decrypt(DestroyableSecretKey demKey) {
        var processor = algorithm.dem.beginDecryption(demKey, siv);
        for (var packet : packets) {
            if (packet.isEncrypted()) {
                processor.authenticate(packet.getPacketHeader()).decryptAndAuthenticate(packet.data);
            } else {
                processor.authenticate(packet.getPacketHeader(), packet.data);
            }
        }
        return processor.verify();
    }

    private Optional<List<byte[]>> decompressAndVerifyCaveats(DestroyableSecretKey caveatKey) {
        var header = getHeader();
        var compressionAlgorithm = header.getString("zip", "none");
        var compression = CompressionAlgorithm.get(compressionAlgorithm);
        var packets = this.packets.stream().map(packet -> packet.decompress(compression)).collect(toList());
        var computedTag = caveatKey.getEncoded();

        for (var packet : packets) {
            if (packet.getType() == PacketType.FIRST_PARTY_CAVEAT) {
                computedTag = Arrays.copyOf(Crypto.hmac(new DestroyableSecretKey("HmacSHA256", computedTag)), 16);
            }
        }
        if (MessageDigest.isEqual(computedTag, this.tag)) {
            return Optional.of(packets.stream().map(Packet::toBytes).collect(Collectors.toUnmodifiableList()));
        } else {
            System.out.println("Tag mismatch:\nexpected="+ hex(this.tag) + "\ncomputed=" + hex(computedTag));
            return Optional.empty();
        }
    }

    public JsonObject getHeader() {
        var headerPacket = packets.get(0);
        if (headerPacket.getType() == PacketType.HEADER) {
            var headerString = new String(headerPacket.data, UTF_8);
            try {
                return JsonParser.object().from(headerString);
            } catch (JsonParserException e) {
                throw new IllegalStateException("Unable to parse header", e);
            }
        }
        return new JsonObject();
    }

    static class Packet {
        static final byte FLAG_ENCRYPTED = (1 << 4);
        static final byte FLAG_COMPRESSED = (1 << 5);

        private final PacketType type;
        private final byte flags;
        private final byte[] data;

        Packet(PacketType type, byte flags, byte[] data) {
            this.data = data;
            this.type = type;
            this.flags = flags;
        }

        Packet(byte header, byte[] data) {
            this(PacketType.values()[header & 0x0F], (byte)(header & 0xF0), data);
        }

        PacketType getType() {
            return type;
        }

        byte[] getPacketHeader() {
            return new byte[] { (byte) (type.ordinal() | flags) };
        }

        byte[] toBytes() {
            byte[] packet = new byte[data.length + 1];
            packet[0] = getPacketHeader()[0];
            System.arraycopy(data, 0, packet, 1, data.length);
            return packet;
        }

        boolean isEncrypted() {
            return (flags & FLAG_ENCRYPTED) == FLAG_ENCRYPTED;
        }

        boolean isCompressed() {
            return (flags & FLAG_COMPRESSED) == FLAG_COMPRESSED;
        }

        Packet compress(CompressionAlgorithm compressionAlgorithm) {
            if (isCompressed()) {
                var compressed = compressionAlgorithm.compress(data);
                return new Packet(type, flags, compressed);
            }
            return this;
        }

        Packet decompress(CompressionAlgorithm compressionAlgorithm) {
            if (isCompressed()) {
                var decompressed = compressionAlgorithm.decompress(data);
                return new Packet(type, flags, decompressed);
            }
            return this;
        }
    }

    private enum PacketType {
        HEADER,
        PAYLOAD,
        FIRST_PARTY_CAVEAT,
        THIRD_PARTY_CAVEAT,
        TAG
    }

    public enum PacketOption {
        ENCRYPTED,
        COMPRESSED
    }

    public static class Builder<K, S> {
        private final Algorithm<K,S> algorithm;
        private final S state;

        private final JsonBuilder<JsonObject> header = JsonObject.builder();
        private final List<Packet> packets = new ArrayList<>();

        private Builder(Algorithm<K, S> algorithm, S state) {
            this.algorithm = algorithm;
            this.state = state;
        }

        public Builder<K, S> header(String key, String value) {
            header.value(key, value);
            return this;
        }

        public Builder<K, S> contentType(String contentType) {
            return header("cty", contentType);
        }

        public Builder<K, S> compressionAlgorithm(CompressionAlgorithm compressionAlgorithm) {
            return header("zip", compressionAlgorithm.getIdentifier());
        }

        public Builder<K, S> payload(boolean encrypt, boolean compress, byte[] data) {
            byte flags = (byte) ((encrypt ? Packet.FLAG_ENCRYPTED : 0) | (compress ? Packet.FLAG_COMPRESSED : 0));
            packets.add(new Packet(PacketType.PAYLOAD, flags, data));
            return this;
        }

        public Builder<K, S> encryptedPayload(byte[] payload) {
            packets.add(new Packet(PacketType.PAYLOAD, Packet.FLAG_ENCRYPTED, payload));
            return this;
        }

        public Florentine<K, S> build() {
            var header = this.header.done();
            packets.add(0, new Packet(PacketType.HEADER, (byte) 0, JsonWriter.string(header).getBytes(UTF_8)));

            var compressionAlg = header.getString("zip", "none");
            var compression = CompressionAlgorithm.get(compressionAlg);

            var packets =
                    this.packets.stream().map(packet -> packet.compress(compression)).collect(toList());

            var demKey = algorithm.kem.demKey(state);
            try {
                var encryptor = algorithm.dem.beginEncryption(demKey);
                for (var packet : packets) {
                    if (packet.isEncrypted()) {
                        encryptor.authenticate(packet.getPacketHeader()).encryptAndAuthenticate(packet.data);
                    } else {
                        encryptor.authenticate(packet.getPacketHeader(), packet.data);
                    }
                }
                var sivAndCaveatKey = encryptor.done();
                var siv = sivAndCaveatKey.getFirst();
                var caveatKey = sivAndCaveatKey.getSecond();
                var encap = algorithm.kem.authEncap(state, siv);
                var newState = encap.getFirst();
                return new Florentine<>(algorithm, encap.getSecond(), List.copyOf(packets), siv, newState, caveatKey);
            } finally {
                demKey.destroy();
            }
        }
    }
}
