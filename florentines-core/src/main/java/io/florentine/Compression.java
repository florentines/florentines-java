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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public abstract class Compression {
    public static final String DEFLATE = "DEF";

    private static final ConcurrentMap<String, Compression> registry = new ConcurrentHashMap<>();

    abstract String identifier();
    abstract byte[] compress(byte[] uncompressed);
    abstract byte[] decompress(byte[] compressed);

    public static Optional<Compression> get(String algorithm) {
        return Optional.ofNullable(registry.get(algorithm));
    }

    static void register(Compression alg) {
        var old = registry.putIfAbsent(alg.identifier(), alg);
        if (old != null && old != alg) {
            throw new IllegalStateException("Algorithm already registered with conflicting implementation");
        }
    }

    final static class Deflate extends Compression {
        static final Compression INSTANCE = new Deflate();

        private Deflate() {}

        @Override
        String identifier() {
            return "DEF";
        }

        @Override
        public byte[] compress(byte[] uncompressed) {
            var baos = new ByteArrayOutputStream();
            try (var out = new DeflaterOutputStream(baos, new Deflater(Deflater.BEST_COMPRESSION, false))) {
                out.write(uncompressed);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return baos.toByteArray();
        }

        @Override
        public byte[] decompress(byte[] compressed) {
            int maxAllowed = 4 * 1024 * 1024;
            var baos = new ByteArrayOutputStream();
            try (var in = new InflaterInputStream(new ByteArrayInputStream(compressed), new Inflater(false))) {
                var buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    baos.write(buffer, 0, read);
                    if (baos.size() > maxAllowed) {
                        throw new SecurityException("Decompressed content exceeds maximum allowed size");
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return baos.toByteArray();
        }
    }
}
