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

package io.florentine.crypto;

import io.florentine.Require;
import io.florentine.Utils;
import software.pando.crypto.nacl.Bytes;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

public abstract class CommittingDEM implements Identifiable {
    private final String identifier;

    CommittingDEM(String identifier) {
        this.identifier = Require.notBlank(identifier, "identifier");
    }

    @Override
    public final String identifier() {
        return identifier;
    }

    public DestroyableSecretKey freshKey() {
        return new DestroyableSecretKey(Bytes.secureRandom(32), identifier);
    }

    abstract EncapsulatedData encapsulate(SecretKey demKey, List<Record> records);
    abstract Optional<DestroyableSecretKey> decapsulate(SecretKey demKey, List<Record> records, byte[] commitment);

    byte[] wrap(SecretKey wrapKey, SecretKey keyToWrap) {
        var keyMaterial = keyToWrap.getEncoded();
        try {
            var record = new WrappedKey(keyMaterial, keyToWrap.getAlgorithm());
            var encaps = encapsulate(wrapKey, List.of(record));
            assert encaps.commitment.length < 256;
            return Utils.concat(new byte[] { (byte) encaps.commitment.length }, encaps.commitment, keyMaterial);
        } finally {
            Utils.wipe(keyMaterial);
        }
    }

    Optional<DestroyableSecretKey> unwrap(SecretKey unwrapKey, byte[] wrappedKey, String algorithm) {
        var len = wrappedKey[0] & 0xFF;
        if (len < 12) { return Optional.empty(); }
        var tag = Arrays.copyOfRange(wrappedKey, 1, 1+len);
        var keyMaterial = Arrays.copyOfRange(wrappedKey, 1+len, wrappedKey.length);
        var record = new WrappedKey(keyMaterial, algorithm);
        return decapsulate(unwrapKey, List.of(record), tag)
                .map(ignored -> new DestroyableSecretKey(keyMaterial, algorithm));
    }

    public record EncapsulatedData(byte[] commitment, DestroyableSecretKey nextDemKey) {}

    public interface Record {
        byte[] secretContent();
        byte[] publicContent();
        byte[] context();
    }

    private record WrappedKey(byte[] keyMaterial, String algorithm) implements Record {
        @Override
        public byte[] secretContent() {
            return keyMaterial;
        }

        @Override
        public byte[] publicContent() {
            return Utils.emptyBytes();
        }

        @Override
        public byte[] context() {
            return algorithm.getBytes(UTF_8);
        }
    }

    public static void main(String... args) throws Exception {
        try (var in = Files.newBufferedReader(Path.of("/tmp/test.txt"))) {
            var line = in.readLine();
            while (line != null) {
                var firstLineOfGroup = line;
                int count = 0;
                do { count++; } while ((line = in.readLine()) != null && line.equals(firstLineOfGroup));
                System.out.printf("%s -> %d%n", firstLineOfGroup, count);
            }
        }
    }
}
