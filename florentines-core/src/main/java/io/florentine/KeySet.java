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
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

public final class KeySet {
    private final String application;
    private final byte[] partyInfo; // Maybe a URI?
    private final List<Entry> keys = new CopyOnWriteArrayList<>();

    public KeySet(String application, byte[] partyInfo) {
        this.application = application;
        this.partyInfo = partyInfo.clone();
    }

    public String getApplication() {
        return application;
    }

    public byte[] getPartyInfo() {
        return partyInfo.clone();
    }

    public KeySet generateKeysFor(KEM kem) {
        var keys = kem.generateKeyPair();
        return add(keys.getPrivate(), keys.getPublic(), kem);
    }

    public KeySet add(Key secretKey, PublicKey publicKey, KEM kem) {
        keys.addFirst(new Entry(Optional.of(secretKey), publicKey, kem));
        return this;
    }

    public KeySet add(PublicKey publicKey, KEM kem) {
        keys.addFirst(new Entry(Optional.empty(), publicKey, kem));
        return this;
    }

    Optional<Entry> find(KEM kem, boolean requireSecretKey) {
        return keys.stream()
                .filter(e -> e.kem == kem)
                .filter(e -> !requireSecretKey || e.secretKey.isPresent())
                .findFirst();
    }

    record Entry(Optional<Key> secretKey, PublicKey publicKey, KEM kem) {}

}
