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

public final class Florentine {

    static class Packet {
        static final byte FLAG_ENCRYPTED = (1 << 0);
        static final byte FLAG_COMPRESSED = (1 << 1);
        private final byte[] data;

        Packet(PacketType type, byte flags, byte[] data) {
            this.data = new byte[data.length + 2];
            this.data[0] = (byte) type.ordinal();
            this.data[1] = flags;
            System.arraycopy(data, 0, this.data, 2, data.length);
        }

        PacketType getType() {
            return PacketType.values()[data[0]];
        }

        boolean isEncrypted() {
            return (data[1] & FLAG_ENCRYPTED) == FLAG_ENCRYPTED;
        }

        boolean isCompressed() {
            return (data[1] & FLAG_COMPRESSED) == FLAG_COMPRESSED;
        }
    }

    private enum PacketType {
        HEADER
    }
}
