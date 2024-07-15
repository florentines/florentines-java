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

import static io.florentine.Florentine.RecordType.CAVEAT_KEY;
import static io.florentine.Florentine.RecordType.HEADER;
import static io.florentine.Florentine.RecordType.PAYLOAD;
import static java.util.Collections.unmodifiableMap;
import static java.util.Objects.requireNonNull;
import static org.msgpack.value.ValueFactory.newBoolean;
import static org.msgpack.value.ValueFactory.newMap;
import static org.msgpack.value.ValueFactory.newString;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageTypeCastException;
import org.msgpack.value.ImmutableMapValue;
import org.msgpack.value.ImmutableStringValue;
import org.msgpack.value.ImmutableValue;

import io.florentine.keys.PrivateKeySet;
import io.florentine.keys.PublicKeySet;

public final class Florentine {

    private final List<Record> records;
    private final DEM dem;
    private final Map<String, ImmutableValue> headers;

    private DataKey caveatKey;

    private Florentine(List<Record> records, DataKey caveatKey) {
        this.records = requireNonNull(records);
        this.caveatKey = requireNonNull(caveatKey);
        this.headers = findHeader(records);

        var demIdentifier = headers.getOrDefault("dem", newString(DEM.DEFAULT_ALGORITHM)).asStringValue().asString();
        this.dem = DEM.lookup(demIdentifier)
                .orElseThrow(() -> new UnsupportedOperationException("Unknown DEM algorithm"));
    }

    private void append(Record record) {
        assert record.type() != RecordType.CAVEAT_KEY;
        var newKey = dem.encapsulate(caveatKey, List.of(record));
        caveatKey.destroy();
        caveatKey = newKey;
        records.add(record);
    }

    private static Map<String, ImmutableValue> findHeader(List<Record> records) {
        var headerRecord = records.stream()
                .filter(record -> record.type == HEADER)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("missing header record"));

        try (var unpacker = MessagePack.newDefaultUnpacker(headerRecord.content(), 0, headerRecord.contentLength())) {
            return convertHeaders(unpacker.unpackValue().asMapValue());
        } catch (MessageTypeCastException e) {
            throw new IllegalStateException("header record is invalid");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Map<String, ImmutableValue> convertHeaders(ImmutableMapValue headerMap) {
        var headers = new LinkedHashMap<String, ImmutableValue>(headerMap.size());
        for (var entry : headerMap.entrySet()) {
            headers.put(entry.getKey().asStringValue().asString(), entry.getValue().immutableValue());
        }
        return unmodifiableMap(headers);
    }

    public static Optional<Florentine> readFrom(InputStream in) throws IOException {
        int lastRecordType = -1;
        var records = new ArrayList<Record>();
        DataKey caveatKey = null;
        while (true) {
            var record = Record.readFrom(in);
            if (record == null) {
                break;
            }
            int newRecordType = record.type().value;
            if (newRecordType < lastRecordType) {
                return Optional.empty();
            }
            lastRecordType = newRecordType;

            if (record.type() == CAVEAT_KEY) {
                caveatKey = new DataKey(record.content(), "HMAC");
            }
            records.add(record);
        }

        return Optional.of(new Florentine(records, caveatKey));
    }

    public static Builder createFrom(PrivateKeySet localParty) {
        return new Builder(localParty);
    }

    public static class Builder {
        // Only 1 compression algorithm supported for now, so hard-code it
        final Compression compression = Compression.DEFLATE;
        Padding padding = Padding.padme(32);
        final PrivateKeySet localParty;
        final Map<ImmutableStringValue, ImmutableValue> headers = new LinkedHashMap<>();
        final List<Record> records = new ArrayList<>();
        final Set<PublicKeySet> remoteParties = new LinkedHashSet<>();
        String applicationLabel;

        Builder(PrivateKeySet localParty) {
            this.localParty = requireNonNull(localParty);
        }

        public Builder applicationLabel(String label) {
            this.applicationLabel = requireNonNull(applicationLabel);
            return this;
        }

        public Builder to(PublicKeySet... remoteParties) {
            return to(List.of(remoteParties));
        }

        public Builder to(Collection<PublicKeySet> remoteParties) {
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

        public Builder padding(Padding padding) {
            this.padding = requireNonNull(padding);
            return this;
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
            if (encrypted) {
                flags.add(RecordFlag.ENCRYPTED);
            } else if (flags.contains(RecordFlag.ENCRYPTED)) {
                throw new IllegalArgumentException("Cannot encrypt public payload!");
            }
            if (flags.contains(RecordFlag.COMPRESSED)) {
                payload = compression.compress(payload);
            }
            var length = payload.length;
            if (flags.contains(RecordFlag.PADDED)) {
                var padded = padding.pad(payload, payload.length);
                payload = padded.bytes();
                length = padded.length();
            }

            records.add(new Record(PAYLOAD, payload, length, flags));
            return this;
        }

        public Florentine build() {
            var localKeys = localParty.primary();
            var kem = localKeys.algorithm().kem();
            var dem = localKeys.algorithm().dem();
            headers.put(newString("dem"), newString(dem.identifier()));
            var compiledHeaders = newMap(headers);
            try (var packer = MessagePack.newDefaultBufferPacker()) {
                compiledHeaders.writeTo(packer);
                var headerRecord = new Record(HEADER, packer.toMessageBuffer().array());
                records.add(0, headerRecord);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            // Encrypt
            var kemState = kem.begin(localParty, remoteParties);
            try (var key = kemState.key()) {
                var caveatKey = dem.encapsulate(key, records);
                var tag = dem.tag(caveatKey);
                var tagRecord = new Record(RecordType.TAG, tag);
                caveatKey = dem.encapsulate(caveatKey, List.of(tagRecord));
                records.add(tagRecord);

                var encapsulation = kemState.encapsulate(tag);
                records.add(0, new Record(RecordType.PREAMBLE, encapsulation.encapsulatedKey()));
                // TODO: communicate the reply state - in the Florentine or separate?
                return new Florentine(records, caveatKey);
            }
        }
    }

    record Record(RecordType type, byte[] content, int contentLength, EnumSet<RecordFlag> flags) {

        Record(RecordType type, byte[] content, RecordFlag... flags) {
            this(type, content, content.length, setOf(flags));
        }

        Record(byte header, byte[] content) {
            this(RecordType.fromHeader(header), content, content.length, RecordFlag.fromHeader(header));
        }

        private static EnumSet<RecordFlag> setOf(RecordFlag[] flags) {
            var result = EnumSet.noneOf(RecordFlag.class);
            result.addAll(List.of(flags));
            return result;
        }

        boolean isEncrypted() {
            return flags.contains(RecordFlag.ENCRYPTED);
        }

        byte[] header() {
            // header is 4-bit type followed by 4 flag bits
            byte header = type.value;
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

        static Record readFrom(InputStream in) throws IOException {
            long length = readVarInt(in);
            if (length < 1 || length > 65536) {
                throw new IOException("invalid record");
            }
            byte header = (byte) in.read();
            if (header == -1) {
                return null;
            }
            var content = in.readNBytes((int) length - 1);
            return new Record(header, content);
        }
    }

    /**
     * Optional processing that can be applied to records on the wire.
     */
    public enum RecordFlag {
        /**
         * The content of the record is compressed.
         */
        COMPRESSED(0),
        /**
         * The content of the record is encrypted.
         */
        ENCRYPTED(1),
        /**
         * The content of the record is padded to hide its length.
         */
        PADDED(2),
        /**
         * Indicates that the record represents a critical feature that recipients must know how to process. If the
         * recipient doesn't understand a critical record, then it must halt further processing of the Florentine.
         * For example, if a caveat is marked as critical, then an implementation that doesn't understand the caveat
         * must treat the entire Florentine as unverified.
         */
        CRITICAL(3);

        final int bitPosition;

        RecordFlag(int bitPosition) {
            this.bitPosition = bitPosition;
        }

        static EnumSet<RecordFlag> fromHeader(byte header) {
            var options = EnumSet.noneOf(RecordFlag.class);
            for (var flag : values()) {
                if ((header & (1 << flag.bitPosition)) != 0) {
                    options.add(flag);
                }
            }
            return options;
        }
    }

    enum RecordType {
        PREAMBLE(0x00),
        HEADER(0x10),
        PAYLOAD(0x20),
        TAG(0x50),
        CAVEAT(0xa0),
        CAVEAT_KEY(0xf0);

        final byte value;

        RecordType(int value) {
            this.value = (byte) value;
        }

        static RecordType fromHeader(byte header) {
            for (var candidate : values()) {
                if (candidate.value == (header & 0xF0)) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException("unknown record type");
        }
    }

    static void writeVarInt(OutputStream out, long value) throws IOException {
        if (value == 0L) {
            out.write(0);
        }
        while (value > 0L) {
            int b = (int) (value & 0x7F);
            if (value > 0x7F) {
                b |= 0x80;
            }
            out.write(b);
            value >>>= 7;
        }
    }

    static long readVarInt(InputStream in) throws IOException {
        int b;
        long value = 0L, shift = 0L;
        do {
            b = in.read();
            if (b == -1) {
                throw new EOFException();
            }
            value |= (long) (b & 0x7F) << shift;
            shift += 7L;
        } while ((b & 0x80) == 0x80 && shift < 64);

        if (shift >= 64) {
            throw new IOException("varint too large");
        }
        return value;
    }
}
