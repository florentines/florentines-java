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

package io.florentine.keys;

import com.grack.nanojson.JsonArray;
import com.grack.nanojson.JsonObject;
import io.florentine.Base64url;
import io.florentine.Require;
import io.florentine.kem.AuthKEM;
import org.msgpack.core.MessagePack;
import org.msgpack.value.Value;
import org.msgpack.value.ValueFactory;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import static java.util.Collections.unmodifiableList;
import static java.util.Collections.unmodifiableSortedSet;
import static org.msgpack.value.ValueFactory.newArray;
import static org.msgpack.value.ValueFactory.newBinary;
import static org.msgpack.value.ValueFactory.newMapBuilder;
import static org.msgpack.value.ValueFactory.newString;

public final class PublicKeySet {
    private final String application;
    private final SortedSet<String> supportedDems;
    private final List<PublicKeyInfo> keys;

    private PublicKeySet(Builder builder) {
        application = Require.notBlank(builder.application, "application");
        supportedDems = Require.notEmpty(unmodifiableSortedSet(builder.supportedDems), "dems");
        keys = Require.notEmpty(unmodifiableList(builder.keys), "keys");
    }

    public record PublicKeyInfo(String kem, byte[] pk) {
        public PublicKeyInfo {
            kem = Require.notBlank(kem, "kem");
            pk = Require.notEmpty(pk, "pk").clone();
        }

        @Override
        public byte[] pk() {
            return pk.clone();
        }

        public Optional<PublicKey> publicKey(Map<String, AuthKEM> supportedKems) {
            return Optional.ofNullable(supportedKems.get(kem)).flatMap(kem -> kem.decodePublicKey(pk));
        }
    }

    public JsonObject toJson() {
        var pks = JsonArray.builder();
        for (var pk : keys) {
            pks.object(Map.of("kem", pk.kem, "pub", Base64url.encode(pk.pk)));
        }
        return JsonObject.builder()
                .value("app", application)
                .array("dem", supportedDems)
                .array("pks", pks.done())
                .done();
    }

    public byte[] toMessagePack() {
        try (var packer = MessagePack.newDefaultBufferPacker()) {
            var map = newMapBuilder()
                    .put(newString("app"), newString(application))
                    .put(newString("dem"), newArray(supportedDems.stream().map(ValueFactory::newString).toList()))
                    .put(newString("pks"), newArray(pks()))
                    .build();
            map.writeTo(packer);
            return packer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Value[] pks() {
        var result = new Value[keys.size()];
        int i = 0;
        for (var pk : keys) {
            result[i++] = newMapBuilder()
                    .put(newString("kem"), newString(pk.kem))
                    .put(newString("pub"), newBinary(pk.pk))
                    .build();
        }
        return result;
    }

    private static SortedSet<String> sorted(Set<String> xs) {
        return new TreeSet<>(xs);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * {@code PublicKeySet} builder static inner class.
     */
    public static final class Builder {
        private String application;
        private final SortedSet<String> supportedDems = new TreeSet<>();
        private final List<PublicKeyInfo> keys = new ArrayList<>();

        private Builder() {
        }


        /**
         * Sets the {@code application} and returns a reference to this Builder enabling method chaining.
         *
         * @param app the {@code application} to set
         * @return a reference to this Builder
         */
        public Builder application(String app) {
            this.application = Require.notBlank(app, "application");
            return this;
        }

        /**
         * Sets the {@code supportedDems} and returns a reference to this Builder enabling method chaining.
         *
         * @param dems the {@code supportedDems} to set
         * @return a reference to this Builder
         */
        public Builder supportedDems(Collection<String> dems) {
            supportedDems.addAll(Require.notEmpty(dems, "dems"));
            return this;
        }

        public Builder supportedDem(String dem) {
            supportedDems.add(Require.notBlank(dem, "dem"));
            return this;
        }

        public Builder publicKey(String kem, byte[] pk) {
            keys.add(new PublicKeyInfo(kem, pk));
            return this;
        }


        /**
         * Returns a {@code PublicKeySet} built from the parameters previously set.
         *
         * @return a {@code PublicKeySet} built with parameters of this {@code PublicKeySet.Builder}
         */
        public PublicKeySet build() {
            return new PublicKeySet(this);
        }
    }
}
