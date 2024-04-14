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
import java.io.UncheckedIOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public enum Compression {
    DEFLATE {
        @Override
        byte[] compress(byte[] input) {
            var baos = new ByteArrayOutputStream();
            try (var out = new DeflaterOutputStream(baos, new Deflater(Deflater.DEFLATED, true))) {
                out.write(input);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            return baos.toByteArray();
        }

        @Override
        byte[] decompress(byte[] input) {
            var baos = new ByteArrayOutputStream();
            var buffer = new byte[8192];
            try (var in = new InflaterInputStream(new ByteArrayInputStream(input), new Inflater(true))) {
                int read;
                while ((read = in.read(buffer)) > 0) {
                    baos.write(buffer, 0, read);
                    if (baos.size() > MAX_DECOMPRESSED_SIZE) {
                        throw new UncheckedIOException(new IOException("Decompressed data exceeds maximum size"));
                    }
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            return baos.toByteArray();
        }
    };

    static final int MAX_DECOMPRESSED_SIZE = 4 * 1024 * 1024;

    abstract byte[] compress(byte[] input);
    abstract byte[] decompress(byte[] input);
}
