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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

final class DeflateCompressionAlgorithm implements CompressionAlgorithm {
    @Override
    public byte[] compress(byte[] input) {
        var baos = new ByteArrayOutputStream();
        try (var out = new DeflaterOutputStream(baos, new Deflater(Deflater.DEFLATED, true))) {
            out.write(input);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return baos.toByteArray();
    }

    @Override
    public byte[] decompress(byte[] input) {
        return new byte[0];
    }
}
