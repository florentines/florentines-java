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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

final class FieldInputStream extends FilterInputStream {
    FieldInputStream(InputStream in) {
        super(in);
    }

    public int readLength() throws IOException {
        var bytes = in.readNBytes(2);
        return (bytes[0] & 0xFF) << 8 | (bytes[1] & 0xFF);
    }

    public String readString() throws IOException {
        int length = readLength();
        var utf8 = in.readNBytes(length);
        return new String(utf8, UTF_8);
    }
}
