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
import java.util.Optional;

import org.slf4j.Logger;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import io.florentines.Florentine.Packet;
import io.florentines.Florentine.PacketType;

final class SerializationFormatV1 implements SerializationFormat {
    private static final Logger logger = RedactedLogger.getLogger(SerializationFormatV1.class);

    @Override
    public void writeTo(OutputStream outputStream, Florentine florentine) throws IOException {
        logger.trace("Writing Florentine to output stream: {}", outputStream);
        var out = new CborEncoder(outputStream);
        try {
            logger.trace("Writing preamble: {} and SIV: {}", florentine.preamble, florentine.siv);
            var builder = new CborBuilder()
                    .add(florentine.preamble)
                    .add(florentine.siv);

            for (var packet : florentine.packets) {
                logger.trace("Writing packet: {}", packet);
                builder.add(packet.toBytes());
            }

            var tagPacket = new Packet(PacketType.TAG, (byte) 0, florentine.caveatKey.getEncoded());
            logger.trace("Writing tag: {}", florentine.caveatKey);
            builder.add(tagPacket.toBytes());
            out.encode(builder.build());
        } catch (CborException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new IOException(e);
        }
    }

    @Override
    public Optional<Florentine> readFrom(InputStream inputStream, Algorithm algorithm) throws IOException {
        logger.debug("Reading Florentine (alg={}) from input stream: {}", algorithm, inputStream);
        var in = new CborDecoder(inputStream);
        var preamble = Utils.readDataItem(in, ByteString.class).getBytes();
        logger.trace("Preamble: {} (len={})", preamble, preamble.length);
        var siv = Utils.readDataItem(in, ByteString.class).getBytes();
        if (siv.length != 16) {
            return Optional.empty();
        }
        logger.trace("SIV: {}", siv);

        Packet packet = null;
        var packets = new ArrayList<Packet>();
        do {
            if (packet != null) {
                packets.add(packet);
            }

            var data = Utils.readDataItem(in, ByteString.class).getBytes();
            packet = new Packet(data);
            logger.trace("Read packet: {}", packet);
        } while (packet.getType() != PacketType.TAG);

        var caveatKey = algorithm.dem.importKey(packet.getData());
        return Optional.of(new Florentine(algorithm, preamble, packets, siv, null, caveatKey));
    }
}
