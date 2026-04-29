/*
 * Copyright 2026 Neil Madden.
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

package io.florentine.crypto;

import org.testng.annotations.Test;

import java.util.HexFormat;

import static java.nio.charset.StandardCharsets.*;
import static org.assertj.core.api.Assertions.*;

public class ChaCha12Test {

    @Test
    public void testQuarterRound() {
        // given
        int[] state = new int[] {0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567};

        // when
        state[0] += state[1];
        state[3] = Integer.rotateLeft(state[3] ^ state[0], 16);

        state[2] += state[3];
        state[1] = Integer.rotateLeft(state[1] ^ state[2], 12);

        state[0] += state[1];
        state[3] = Integer.rotateLeft(state[3] ^ state[0], 8);

        state[2] += state[3];
        state[1] = Integer.rotateLeft(state[1] ^ state[2], 7);

        // then
        assertThat(state).containsExactly(0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb);
    }

    @Test
    public void testBlockFunction() {
        // given
        byte[] key = HexFormat.ofDelimiter(":").parseHex(
                "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");
        byte[] nonce = HexFormat.ofDelimiter(":").parseHex("00:00:00:09:00:00:00:4a:00:00:00:00");
        int blockCounter = 1;
        var chacha12 = new ChaCha12();

        // when
        int[] state = ChaCha12.initialState(key, nonce, blockCounter);
        assertThat(state).containsExactly(
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                0x00000001, 0x09000000, 0x4a000000, 0x00000000);

        int[] finalState = chacha12.blockFunction(state);
        assertThat(finalState).containsExactly(
                0x66138b7f, 0x9937c777, 0x7d77e7e3, 0xccd8e616,
                0x39ce87c7, 0xc6904969, 0x0287e028, 0x0b19e99c,
                0x1ae34bda, 0x0221fec3, 0x7c73ada9, 0xb0a32ff8,
                0x33b6686e, 0x825cc671, 0x0a049972, 0xa0a81bde);
    }

    @Test
    public void testEncryption() {
        // given
        var plaintext = ("Ladies and Gentlemen of the class of '99: " +
                "If I could offer you only one tip for the future," +
                " sunscreen would be it.").getBytes(UTF_8);
        byte[] key = HexFormat.ofDelimiter(":").parseHex(
                "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");
        byte[] nonce = HexFormat.ofDelimiter(":").parseHex("00:00:00:09:00:00:00:4a:00:00:00:00");
        int blockCounter = 1;
        var chacha12 = new ChaCha12();

        // when
        int[] state = ChaCha12.initialState(key, nonce, blockCounter);
        chacha12.encrypt(state, plaintext, 0, plaintext.length);

        // then
        assertThat(plaintext).asHexString().isEqualToIgnoringWhitespace(
                "33 EA 77 0F 12 B4 17 F8 8D 83 57 3A 73 88 AC A0 " +
                "A2 EA AB 57 49 26 F6 E6 5C 88 E2 22 FF 85 78 78 " +
                "A9 6B 8C 7C E3 D9 18 3B 93 8D 3A 1A D8 66 83 D3 " +
                "01 1D DA 57 51 A9 3A E4 17 EB 24 73 B1 6E 88 CF " +
                "B8 FC 7E 5C 97 A7 7C 57 79 42 2F 13 F8 0E AC 8C " +
                "13 5D E8 76 EE 9E 6B FC 90 E8 46 80 B0 B3 DE 09 " +
                "5D A0 B3 18 92 BB B8 5B C8 AF 15 41 C9 B6 E3 2A " +
                "74 2E");
    }
}