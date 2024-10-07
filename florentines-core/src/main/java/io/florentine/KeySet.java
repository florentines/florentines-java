/*
 * Copyright 2024 Neil Madden.
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

package io.florentine;

import java.security.Key;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public final class KeySet {
    private final String application;
    private final String identifier;
    private final List<Entry> keys = new CopyOnWriteArrayList<>();
    private final Set<String> supportedDems;

    public KeySet(String application, String identifier, Collection<String> supportedDems) {
        this.application = Require.notBlank(application, "application");
        this.identifier = Require.notBlank(identifier, "identifier");
        this.supportedDems = Set.copyOf(Require.notEmpty(supportedDems, "supported DEMs"));
    }

    public String application() {
        return application;
    }

    public Set<String> supportedDems() {
        return supportedDems;
    }

    public KeySet generateKeysFor(String kemAlg) {
        var kem = KEM.lookup(kemAlg).orElseThrow(() -> new IllegalArgumentException("Unknown KEM algorithm"));
        var keys = kem.generateKeyPair();
        return add(keys.getPrivate(), keys.getPublic(), kem.identifier());
    }

    public KeySet add(Key secretKey, PublicKey publicKey, String kem) {
        keys.addFirst(new Entry(Optional.of(secretKey), publicKey, kem));
        return this;
    }

    public KeySet add(PublicKey publicKey, String kem) {
        keys.addFirst(new Entry(Optional.empty(), publicKey, kem));
        return this;
    }

    Optional<Entry> find(String kem) {
        return keys.stream()
                .filter(e -> Objects.equals(e.kem, kem))
                .findFirst();
    }

    public KeySet toPublicKeySet() {
        var pubKeys = new KeySet(application, identifier, supportedDems);
        pubKeys.keys.addAll(this.keys.stream()
                .map(entry -> new Entry(Optional.empty(), entry.publicKey(), entry.kem()))
                .toList());
        return pubKeys;
    }

    record Entry(Optional<Key> secretKey, PublicKey publicKey, String kem) {}

}
