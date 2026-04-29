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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ChaCha12 implements StreamCipher {

    private static final int BLOCK_SIZE_INTS = 16;
    private static final int BLOCK_COUNTER_IDX = 12;

    @Override
    public DataEncryptionKey importKey(byte[] keyMaterial, int offset) {
        return new DataEncryptionKey(keyMaterial, offset, 32, "ChaCha12");
    }

    @Override
    public CipherState begin(DataEncryptionKey key, byte[] nonce) {
        if (!"ChaCha12".equals(key.getAlgorithm()) || key.getEncoded().length != getKeyLengthBytes()) {
            throw new IllegalArgumentException("invalid key");
        }
        if (nonce.length < getNonceLengthBytes()) {
            throw new IllegalArgumentException("invalid nonce");
        }

        return new State(key.getEncoded(), nonce);
    }

    @Override
    public int getKeyLengthBytes() {
        return 32;
    }

    @Override
    public int getNonceLengthBytes() {
        return 12;
    }

    private final class State implements CipherState {
        private int[] state;

        private State(byte[] key, byte[] nonce) {
            this.state = initialState(key, nonce, 0);
        }

        @Override
        public CipherState encipher(byte[] plaintext, int offset, int length) {
            encrypt(state, plaintext, offset, length);
            return this;
        }
    }

    static int[] initialState(byte[] key, byte[] nonce, int initialCounter) {
        assert key.length == 32 && nonce.length >= 12;

        int[] state = new int[BLOCK_SIZE_INTS];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(state, 4, 8);
        state[BLOCK_COUNTER_IDX] = initialCounter; // Block counter
        ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(state, 13, 3);

        return state;
    }

    private final int[] stateCopy = new int[BLOCK_SIZE_INTS];
    int[] blockFunction(int[] state) {
        int sc0 = state[0];
        int sc1 = state[1];
        int sc2 = state[2];
        int sc3 = state[3];
        int sc4 = state[4];
        int sc5 = state[5];
        int sc6 = state[6];
        int sc7 = state[7];
        int sc8 = state[8];
        int sc9 = state[9];
        int sc10 = state[10];
        int sc11 = state[11];
        int sc12 = state[12];
        int sc13 = state[13];
        int sc14 = state[14];
        int sc15 = state[15];

        for (int round = 0; round < BLOCK_COUNTER_IDX; round += 2) {
            sc0 += sc4;
            sc12 = Integer.rotateLeft(sc12 ^ sc0, 16);

            sc8 += sc12;
            sc4 = Integer.rotateLeft(sc4 ^ sc8, 12);

            sc0 += sc4;
            sc12 = Integer.rotateLeft(sc12 ^ sc0, 8);

            sc8 += sc12;
            sc4 = Integer.rotateLeft(sc4 ^ sc8, 7);

            sc1 += sc5;
            sc13 = Integer.rotateLeft(sc13 ^ sc1, 16);

            sc9 += sc13;
            sc5 = Integer.rotateLeft(sc5 ^ sc9, 12);

            sc1 += sc5;
            sc13 = Integer.rotateLeft(sc13 ^ sc1, 8);

            sc9 += sc13;
            sc5 = Integer.rotateLeft(sc5 ^ sc9, 7);

            sc2 += sc6;
            sc14 = Integer.rotateLeft(sc14 ^ sc2, 16);

            sc10 += sc14;
            sc6 = Integer.rotateLeft(sc6 ^ sc10, 12);

            sc2 += sc6;
            sc14 = Integer.rotateLeft(sc14 ^ sc2, 8);

            sc10 += sc14;
            sc6 = Integer.rotateLeft(sc6 ^ sc10, 7);

            sc3 += sc7;
            sc15 = Integer.rotateLeft(sc15 ^ sc3, 16);

            sc11 += sc15;
            sc7 = Integer.rotateLeft(sc7 ^ sc11, 12);

            sc3 += sc7;
            sc15 = Integer.rotateLeft(sc15 ^ sc3, 8);

            sc11 += sc15;
            sc7 = Integer.rotateLeft(sc7 ^ sc11, 7);

            sc0 += sc5;
            sc15 = Integer.rotateLeft(sc15 ^ sc0, 16);

            sc10 += sc15;
            sc5 = Integer.rotateLeft(sc5 ^ sc10, 12);

            sc0 += sc5;
            sc15 = Integer.rotateLeft(sc15 ^ sc0, 8);

            sc10 += sc15;
            sc5 = Integer.rotateLeft(sc5 ^ sc10, 7);

            sc1 += sc6;
            sc12 = Integer.rotateLeft(sc12 ^ sc1, 16);

            sc11 += sc12;
            sc6 = Integer.rotateLeft(sc6 ^ sc11, 12);

            sc1 += sc6;
            sc12 = Integer.rotateLeft(sc12 ^ sc1, 8);

            sc11 += sc12;
            sc6 = Integer.rotateLeft(sc6 ^ sc11, 7);

            sc2 += sc7;
            sc13 = Integer.rotateLeft(sc13 ^ sc2, 16);

            sc8 += sc13;
            sc7 = Integer.rotateLeft(sc7 ^ sc8, 12);

            sc2 += sc7;
            sc13 = Integer.rotateLeft(sc13 ^ sc2, 8);

            sc8 += sc13;
            sc7 = Integer.rotateLeft(sc7 ^ sc8, 7);

            sc3 += sc4;
            sc14 = Integer.rotateLeft(sc14 ^ sc3, 16);

            sc9 += sc14;
            sc4 = Integer.rotateLeft(sc4 ^ sc9, 12);

            sc3 += sc4;
            sc14 = Integer.rotateLeft(sc14 ^ sc3, 8);

            sc9 += sc14;
            sc4 = Integer.rotateLeft(sc4 ^ sc9, 7);
        }

        stateCopy[0] = sc0 + state[0];
        stateCopy[1] = sc1 + state[1];
        stateCopy[2] = sc2 + state[2];
        stateCopy[3] = sc3 + state[3];
        stateCopy[4] = sc4 + state[4];
        stateCopy[5] = sc5 + state[5];
        stateCopy[6] = sc6 + state[6];
        stateCopy[7] = sc7 + state[7];
        stateCopy[8] = sc8 + state[8];
        stateCopy[9] = sc9 + state[9];
        stateCopy[10] = sc10 + state[10];
        stateCopy[11] = sc11 + state[11];
        stateCopy[12] = sc12 + state[12];
        stateCopy[13] = sc13 + state[13];
        stateCopy[14] = sc14 + state[14];
        stateCopy[15] = sc15 +  state[15];

        return stateCopy;
    }

    void encrypt(int[] state, byte[] plaintext, int offset, int length) {
        var block = new int[BLOCK_SIZE_INTS];
        var buffer = ByteBuffer.wrap(plaintext, offset, length).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
        int remaining;
        int limit;
        while ((remaining = buffer.remaining()) > 0) {
            limit = Math.min(remaining, BLOCK_SIZE_INTS);
            buffer.mark();
            buffer.get(block, 0, limit);
            int[] sc = blockFunction(state);
            for (int i = 0; i < limit; ++i) {
                block[i] ^= sc[i];
            }
            buffer.reset().put(block, 0, limit);

            if ((state[BLOCK_COUNTER_IDX] += 1) == 0) {
                throw new IllegalStateException("block counter overflow");
            }
        }
    }
}
