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

import static io.florentine.Florentine.RecordType.HEADER;
import static io.florentine.Florentine.RecordType.PAYLOAD;
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
     * Each record has a length field (encoded as a varint), a single-byte header, and the payload.
     */

    private final List<Record> records;
    private final DEM dem;
    private final AuthKem kem;
    private final Compression compression;

    private DestroyableSecretKey caveatKey;

    private Florentine(Builder builder) {
        this.compression = builder.compression;
        this.dem = builder.localParty.getCryptoSuite().dem();
        this.kem = builder.localParty.getCryptoSuite().kem();

        this.records = builder.records;

        // Encrypt
        var kemState = kem.begin(null, null); // TODO
        try (var key = kemState.key()) {
            var tagAndKey = dem.encrypt(key, records);
            this.caveatKey = tagAndKey.caveatKey();
            var tagRecord = new Record(RecordType.TAG, tagAndKey.tag(), RecordFlag.CRITICAL);
            append(tagRecord);
        }
    }

    private void append(Record record) {
        assert record.type() != RecordType.CAVEAT_KEY;
        var tag = dem.encrypt(caveatKey, List.of(record));
        caveatKey.destroy();
        caveatKey = tag.caveatKey();
        records.add(record);
    }

    public static Builder from(LocalParty localParty) {
        return new Builder(localParty);
    }

    public static class Builder {
        // Only 1 compression algorithm supported for now, so hard-code it
        final Compression compression = Compression.DEFLATE;
        final LocalParty localParty;
        final Map<ImmutableStringValue, ImmutableValue> headers = new LinkedHashMap<>();
        final List<Record> records = new ArrayList<>();
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

        public Builder publicPayload(byte[] payload, RecordFlag... options) {
            return payload(payload, false, options);
        }

        public Builder secretPayload(byte[] payload, RecordFlag... options) {
            return payload(payload, true, options);
        }

        private Builder payload(byte[] payload, boolean encrypted, RecordFlag... options) {
            var flags = EnumSet.noneOf(RecordFlag.class);
            flags.addAll(List.of(options));
            if (flags.contains(RecordFlag.RESERVED)) {
                throw new IllegalArgumentException("invalid flag");
            }
            if (encrypted) {
                flags.add(RecordFlag.ENCRYPTED);
            } else if (flags.contains(RecordFlag.ENCRYPTED)) {
                throw new IllegalArgumentException("Cannot encrypt public payload!");
            }
            if (flags.contains(RecordFlag.COMPRESSED)) {
                payload = compression.compress(payload);
            }

            records.add(new Record(PAYLOAD, payload, flags));
            return this;
        }

        public Florentine build() {
            var compiledHeaders = newMap(headers);
            try (var packer = MessagePack.newDefaultBufferPacker()) {
                compiledHeaders.writeTo(packer);
                var headerRecord = new Record(HEADER, packer.toMessageBuffer().array());
                records.add(0, headerRecord);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return new Florentine(this);
        }
    }

    record Record(RecordType type, byte[] content, EnumSet<RecordFlag> flags) implements DEM.Part {

        Record(RecordType type, byte[] content, RecordFlag... flags) {
            this(type, content, setOf(flags));
        }

        private static EnumSet<RecordFlag> setOf(RecordFlag[] flags) {
            var result = EnumSet.noneOf(RecordFlag.class);
            result.addAll(List.of(flags));
            return result;
        }

        @Override
        public boolean isEncrypted() {
            return flags.contains(RecordFlag.ENCRYPTED);
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

    public enum RecordFlag {
        COMPRESSED(0),
        ENCRYPTED(1),
        CRITICAL(2),
        RESERVED(3);

        final int bitPosition;

        RecordFlag(int bitPosition) {
            this.bitPosition = bitPosition;
        }
    }

    enum RecordType {
        PREAMBLE(0x00),
        HEADER(0x10),
        PAYLOAD(0x20),
        TAG(0x50),
        CAVEAT(0xa0),
        CAVEAT_KEY(0xf0);

        final byte nibble;

        RecordType(int nibble) {
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
