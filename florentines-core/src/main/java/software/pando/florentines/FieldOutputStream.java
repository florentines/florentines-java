/*
 * Copyright 2022 Neil Madden.
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

package software.pando.florentines;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

final class FieldOutputStream extends FilterOutputStream {
    FieldOutputStream(OutputStream out) {
        super(out);
    }

    void writeString(String value) throws IOException {
        byte[] utf8 = value.getBytes(UTF_8);
        writeLength(utf8.length);
        write(utf8);
    }

    void writeLength(int length) throws IOException {
        if (length < 0 || length > 65535) {
            throw new IOException("Invalid length field");
        }
        out.write((length >>> 8) & 0xFF);
        out.write(length & 0xFF);
    }

    byte[] toByteArray() {
        return ((ByteArrayOutputStream) out).toByteArray();
    }
}
