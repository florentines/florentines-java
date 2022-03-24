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
import java.io.OutputStream;
import java.io.UncheckedIOException;

/**
 * Represents an encapsulation of a {@link DEM} key. The encapsulated data can be used by a recipient to recover the
 * DEM key used to encrypt a message.
 */
interface EncapsulatedKey {

    /**
     * Writes the encapsulated key data to the given output stream, returning the number of bytes written.
     *
     * @param outputStream the stream to write the encapsulated key to.
     * @return the number of bytes written to the stream.
     * @throws IOException if an error occurs when writing the encapsulated key.
     */
    void writeTo(OutputStream outputStream) throws IOException;

    /**
     * Converts the encapsulated key into a byte array.
     *
     * @return the encapsulated key as a byte array.
     */
    default byte[] toBytes() {
        try (var baos = new ByteArrayOutputStream()) {
            writeTo(baos);
            return baos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
