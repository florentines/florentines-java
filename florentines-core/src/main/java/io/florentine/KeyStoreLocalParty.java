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

import static java.util.stream.Collectors.toList;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

public final class KeyStoreLocalParty implements LocalParty {
    private final CryptoSuite cryptoSuite;
    private final byte[] partyInfo;
    private final Map<String, byte[]> keyIds;
    private final String activeAlias;
    private final KeyStore keyStore;
    private final KeyStore.ProtectionParameter password;

    public KeyStoreLocalParty(CryptoSuite cryptoSuite, byte[] partyInfo, Map<String, byte[]> keyIds,
                              String activeAlias, KeyStore keyStore, KeyStore.ProtectionParameter password) {
        this.cryptoSuite = cryptoSuite;
        this.partyInfo = partyInfo.clone();
        this.keyIds = keyIds;
        this.activeAlias = activeAlias;
        this.keyStore = keyStore;
        this.password = password;
    }

    @Override
    public byte[] getPartyInfo() {
        return partyInfo.clone();
    }

    @Override
    public KeyPair getStaticKeys() {
        return loadKeyPair(activeAlias).orElseThrow();
    }

    @Override
    public CryptoSuite getCryptoSuite() {
        return cryptoSuite;
    }

    @Override
    public Iterable<KeyPair> getKeysById(byte[] salt, byte[] kid) {
        var candidates = new ArrayList<String>();
        keyIds.forEach((alias, id) -> {
            try (var tmp = HKDF.extract(salt, id)) {
                var saltedId = Arrays.copyOf(tmp.getEncoded(), 4);
                if (Arrays.equals(saltedId, kid)) {
                    candidates.add(alias);
                }
            }
        });

        return candidates.stream()
                .map(this::loadKeyPair)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(toList());
    }

    private Optional<KeyPair> loadKeyPair(String alias) {
        try {
            var keyEntry = keyStore.getEntry(alias, password);
            if (!(keyEntry instanceof KeyStore.PrivateKeyEntry privateKeyEntry)) {
                return Optional.empty();
            }
            var privKey = privateKeyEntry.getPrivateKey();
            var pubKey = privateKeyEntry.getCertificate().getPublicKey();

            return Optional.of(new KeyPair(pubKey, privKey));
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
