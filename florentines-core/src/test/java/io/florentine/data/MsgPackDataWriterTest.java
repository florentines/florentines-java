/*
 * Copyright 2025 Neil Madden.
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

package io.florentine.data;

import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class MsgPackDataWriterTest {
    @Test
    public void testStuff() throws IOException {
        var map = Rank2Map.of(
                "sub", "test subject",
                "aud", Rank1Array.of("foo", "bar"),
                "exp", System.currentTimeMillis() / 1000
        );
        var baos = new ByteArrayOutputStream();
        try (var out = new MsgPackDataWriter(baos)) { out.writeRank2Map(map); }
        hexdump(baos.toByteArray());
    }

    private void hexdump(byte[] data) {
        var last = new StringBuilder();
        for (int i = 0; i < data.length; ++i) {
            if (i % 16 == 0) {
                System.out.printf(" %16s%n", last);
                last.delete(0, last.length());
            } else if (i % 8 == 0) {
                System.out.print("  ");
            }
            if ((data[i] & 0xFF) >= 32 && (data[i] & 0xFF) < 127) {
                last.append((char) data[i]);
            } else {
                last.append('.');
            }
            System.out.printf("%02x ", data[i]);
        }
        var remaining = (16 - (data.length % 16)) % 16;
        System.out.print("   ".repeat(remaining));
        if (remaining > 8) {
            System.out.print("  ");
        }
        System.out.println(" " + last);
    }
}