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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Optional;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Indicates the algorithm used for compression of any payload packets that are marked as compressed.
 */
public enum Compression {
    /**
     * No compression will be used. This effectively ignores the compression flag on any payload packets.
     */
    NONE("none") {
        @Override
        byte[] compress(byte[] input) {
            return input.clone();
        }

        @Override
        byte[] decompress(byte[] input) {
            return input.clone();
        }
    },

    /**
     * The DEFLATE algorithm of RFC 1951. To avoid zip-bomb denial of service attacks, this implementation imposes a
     * maximum size limit of 50MiB on decompressed data. You can set the
     * <code>io.florentines.compression.max_decompressed_size</code> system property to override this limit up to a
     * maximum of {@value Integer#MAX_VALUE}.
     */
    DEFLATE("DEF") {
        private static final boolean NO_GZIP_HEADERS = true;
        private static final int MAX_DECOMPRESSED_SIZE =
                Integer.getInteger("io.florentines.compression.max_decompressed_size", 50 * 1024 * 1024);

        @Override
        byte[] compress(byte[] input) {
            var baos = new ByteArrayOutputStream();
            try (var out = new DeflaterOutputStream(baos,
                    new Deflater(Deflater.DEFAULT_COMPRESSION, NO_GZIP_HEADERS))) {
                out.write(input);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            return baos.toByteArray();
        }

        @Override
        byte[] decompress(byte[] input) {
            var buffer = new byte[2048];
            var out = new ByteArrayOutputStream();
            try (var in = new InflaterInputStream(new ByteArrayInputStream(input), new Inflater(NO_GZIP_HEADERS))) {
                int numRead = in.read(buffer);
                while (numRead > 0) {
                    out.write(buffer, 0, numRead);
                    // Enforce a maximum decompressed size to prevent zip-bomb DoS attacks. The maximum compression
                    // ratio of deflate is approx 1032:1.
                    // See https://security.stackexchange.com/questions/51071/zlib-deflate-decompression-bomb
                    if (out.size() > MAX_DECOMPRESSED_SIZE) {
                        throw new UncheckedIOException(new IOException("Decompressed data exceeded limit"));
                    }
                    numRead = in.read(buffer);
                }

            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            return out.toByteArray();
        }
    };

    private final String identifier;

    Compression(String identifier) {
        this.identifier = identifier;
    }

    public String identifier() {
        return identifier;
    }

    public static Optional<Compression> of(String identifier) {
        for (var candidate : values()) {
            if (candidate.identifier.equals(identifier)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }

    abstract byte[] compress(byte[] input);
    abstract byte[] decompress(byte[] input);
}
