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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;

import org.slf4j.Logger;

import io.florentines.Florentine.Packet;
import io.florentines.Florentine.PacketType;
import io.florentines.io.CborReader;
import io.florentines.io.CborWriter;

final class SerializationFormatV1 implements SerializationFormat {
    private static final Logger logger = RedactedLogger.getLogger(SerializationFormatV1.class);

    @Override
    public void writeTo(OutputStream outputStream, Florentine florentine) throws IOException {
        logger.trace("Writing Florentine to output stream: {}", outputStream);
        var out = new CborWriter(outputStream);
        logger.trace("Writing preamble: {} and SIV: {}", florentine.preamble, florentine.siv);
        out.writeBytes(florentine.preamble);
        out.writeBytes(florentine.siv);
        for (var packet : florentine.packets) {
            logger.trace("Writing packet: {}", packet);
            out.writeBytes(packet.toBytes());
        }

        var tagPacket = new Packet(PacketType.TAG, (byte) 0, florentine.caveatKey.getEncoded());
        logger.trace("Writing tag: {}", florentine.caveatKey);
        out.writeBytes(tagPacket.toBytes());
    }

    @Override
    public Florentine readFrom(InputStream inputStream, Algorithm algorithm) throws IOException {
        logger.debug("Reading Florentine (alg={}) from input stream: {}", algorithm, inputStream);
        var in = new CborReader(inputStream);
        var preamble = in.readBytes();
        logger.trace("Preamble: {} (len={})", preamble, preamble.length);
        var siv = in.readFixedLengthBytes(16);
        logger.trace("SIV: {}", siv);

        Packet packet = null;
        var packets = new ArrayList<Packet>();
        do {
            if (packet != null) {
                packets.add(packet);
            }

            var data = in.readBytes();
            packet = new Packet(data);
            logger.trace("Read packet: {}", packet);
        } while (packet.getType() != PacketType.TAG);

        var caveatKey = algorithm.dem.importKey(packet.getData());
        return new Florentine(algorithm, preamble, packets, siv, null, caveatKey);
    }
}
