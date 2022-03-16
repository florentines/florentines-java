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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toUnmodifiableList;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;

import com.grack.nanojson.JsonBuilder;
import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import com.grack.nanojson.JsonWriter;


public final class Florentine {
    private static final Logger logger = RedactedLogger.getLogger(Florentine.class);

    private static final byte[] HKDF_REPLY_SALT = Crypto.hash("Florentine-In-Reply-To".getBytes(UTF_8));

    private final Algorithm algorithm;
    private final byte[] preamble;
    private final List<Packet> packets;
    private final byte[] siv;
    private ConversationState state;

    private DestroyableSecretKey caveatKey;

    private Florentine(Algorithm algorithm, byte[] preamble, List<Packet> packets, byte[] siv,
            ConversationState state, DestroyableSecretKey caveatKey) {
        this.algorithm = algorithm;
        this.preamble = preamble;
        this.packets = packets;
        this.siv = siv;
        this.state = state;
        this.caveatKey = caveatKey;
    }

    public static <T, S extends ConversationState> Builder builder(Algorithm algorithm,
            SecretKey senderKeys, PublicIdentity... recipients) {
        var state = algorithm.kem.begin(senderKeys, recipients);
        return new Builder(algorithm, state);
    }

    public Florentine copy() {
        return new Florentine(algorithm, preamble, List.copyOf(packets), siv.clone(), state, caveatKey.copy());
    }

    public Florentine restrict(JsonObject caveat) {
        var caveatBytes = JsonWriter.string(caveat).getBytes(UTF_8);
        packets.add(new Packet(PacketType.FIRST_PARTY_CAVEAT, (byte) 0, caveatBytes));
        this.caveatKey = algorithm.prf.apply(caveatKey, caveatBytes);
        return this;
    }

    public Florentine addThirdPartyCaveat(PublicIdentity service, byte[] caveatId) {
        var alg = service.getAlgorithm()
                .orElseThrow(() -> new IllegalArgumentException("Unknown algorithm"));
        var sender = alg.generateKeys(service.getApplication());
        var challenge = Florentine.builder(algorithm, sender, service)
                .encryptedPayload(caveatId)
                .build();
        try (var out = new ByteArrayOutputStream()) {
            challenge.state.writeTo(out);
            var data = out.toByteArray();
            var result = algorithm.dem.beginEncryption(caveatKey).encryptAndAuthenticate(data).done();
            caveatKey.destroy();
            caveatKey = result.getSecond();
            data = Utils.concat(result.getFirst(), data);
            packets.add(new Packet(PacketType.THIRD_PARTY_CAVEAT, Packet.FLAG_ENCRYPTED, data));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return challenge;
    }

    public Builder reply() {
        return new Builder(algorithm, state).inReplyTo(this);
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
            var tag = caveatKey.getEncoded();
            out.writeShort(tag.length);
            out.write(tag);
        } finally {
            out.flush();
        }
    }

    public static <K, S extends ConversationState> Florentine readFrom(Algorithm algorithm,
            InputStream inputStream) throws IOException {
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
        return new Florentine(algorithm, preamble, packets, siv, null, caveatKey);
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

    public static <K, S extends ConversationState> Optional<Florentine> fromString(Algorithm algorithm,
            String stringForm) {
        try (var in = new ByteArrayInputStream(Base64url.decode(stringForm))) {
            return Optional.of(readFrom(algorithm, in));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    public Optional<List<byte[]>> decrypt(SecretKey recipientKey,
            PublicIdentity... expectedSenders) {
        var state = algorithm.kem.begin(recipientKey, expectedSenders);
        return algorithm.kem.authDecap(state, preamble, siv)
                .map(stateAndDemKey -> {
                    this.state = stateAndDemKey.getFirst();
                    return stateAndDemKey.getSecond();
                })
                .flatMap(this::decrypt)
                .flatMap(this::decompressAndVerifyCaveats);
    }

    public Optional<List<byte[]>> decryptReply(Florentine originalMessage) {
        var header = getHeader();
        if (!header.isReply()) {
            return Optional.empty();
        }

        var expectedIrt = Arrays.copyOf(HKDF.extract(originalMessage.siv, HKDF_REPLY_SALT), 4);
        var inReplyTo = Base64url.decode(header.inReplyTo().orElseThrow());
        if (!MessageDigest.isEqual(expectedIrt, inReplyTo)) {
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
                processor.authenticate(packet.getPacketHeader()).authenticate(packet.data);
            }
        }
        return processor.verify();
    }

    private Optional<List<byte[]>> decompressAndVerifyCaveats(DestroyableSecretKey caveatKey) {
        var header = getHeader();
        var compressionAlgorithm = header.compressionAlgorithm();
        var packets = this.packets.stream().map(packet -> packet.decompress(compressionAlgorithm)).collect(toList());

        for (var packet : packets) {
            if (packet.getType() == PacketType.FIRST_PARTY_CAVEAT) {
                caveatKey = algorithm.prf.apply(caveatKey, packet.data);
            }
        }
        if (this.caveatKey.equals(caveatKey)) {
            return Optional.of(packets.stream().map(Packet::toBytes).collect(toUnmodifiableList()));
        } else {
            logger.trace("Tag mismatch: expected={}, computed={}", this.caveatKey, caveatKey);
            return Optional.empty();
        }
    }

    public Header getHeader() {
        var headerPacket = packets.get(0);
        if (headerPacket.getType() == PacketType.HEADER) {
            var headerString = new String(headerPacket.data, UTF_8);
            try {
                return new Header(JsonParser.object().from(headerString));
            } catch (JsonParserException e) {
                throw new IllegalStateException("Unable to parse header", e);
            }
        }
        return new Header(new JsonObject());
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

        Packet compress(Compression compression) {
            if (isCompressed()) {
                var compressed = compression.compress(data);
                return new Packet(type, flags, compressed);
            }
            return this;
        }

        Packet decompress(Compression compression) {
            if (isCompressed()) {
                var decompressed = compression.decompress(data, 1_000_000);
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

    public static class Builder {
        private final Algorithm algorithm;
        private final ConversationState state;

        private final JsonBuilder<JsonObject> header = JsonObject.builder();
        private final List<Packet> packets = new ArrayList<>();

        private Builder(Algorithm algorithm, ConversationState state) {
            this.algorithm = algorithm;
            this.state = state;
        }

        public Builder header(String key, String value) {
            header.value(key, value);
            return this;
        }

        Builder inReplyTo(Florentine original) {
            var id = HKDF.extract(original.siv, HKDF_REPLY_SALT);
            var idStr = Base64url.encode(Arrays.copyOf(id, 4));
            return header(Header.IN_REPLY_TO, idStr);
        }

        public Builder contentType(String contentType) {
            return header(Header.CONTENT_TYPE, contentType);
        }

        public Builder compressionAlgorithm(Compression compression) {
            return header(Header.COMPRESSION_ALGORITHM, compression.getIdentifier());
        }

        public Builder payload(boolean encrypt, boolean compress, byte[] data) {
            byte flags = (byte) ((encrypt ? Packet.FLAG_ENCRYPTED : 0) | (compress ? Packet.FLAG_COMPRESSED : 0));
            packets.add(new Packet(PacketType.PAYLOAD, flags, data));
            return this;
        }

        public Builder encryptedPayload(byte[] payload) {
            packets.add(new Packet(PacketType.PAYLOAD, Packet.FLAG_ENCRYPTED, payload));
            return this;
        }

        public Florentine build() {
            var header = this.header.done();
            packets.add(0, new Packet(PacketType.HEADER, (byte) 0, JsonWriter.string(header).getBytes(UTF_8)));

            var compressionAlg = header.getString("zip", "none");
            var compression = Compression.valueOf(compressionAlg);

            var packets =
                    this.packets.stream().map(packet -> packet.compress(compression)).collect(toList());

            var demKey = algorithm.kem.demKey(state);
            try {
                var encryptor = algorithm.dem.beginEncryption(demKey);
                for (var packet : packets) {
                    if (packet.isEncrypted()) {
                        encryptor.authenticate(packet.getPacketHeader()).encryptAndAuthenticate(packet.data);
                    } else {
                        encryptor.authenticate(packet.getPacketHeader()).authenticate(packet.data);
                    }
                }
                var sivAndCaveatKey = encryptor.done();
                var siv = sivAndCaveatKey.getFirst();
                var caveatKey = sivAndCaveatKey.getSecond();
                var encap = algorithm.kem.authEncap(state, siv);
                var newState = encap.getFirst();
                return new Florentine(algorithm, encap.getSecond(), List.copyOf(packets), siv, newState, caveatKey);
            } finally {
                demKey.destroy();
            }
        }
    }
}
