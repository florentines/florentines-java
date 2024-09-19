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

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Optional;

import javax.security.auth.Destroyable;

public abstract class KEM {
    public abstract String identifier();

    abstract KeyPair generateKeyPair();
    abstract byte[] keyId(byte[] salt, PublicKey publicKey);

    abstract State begin(DEM dem, KeySet local, Collection<KeySet> remote);

    interface State extends Destroyable {
        DataEncapsulationKey key();
        EncapsulatedKey encapsulate(byte[] context);
        Optional<DecapsulatedKey> decapsulate(byte[] encapsulatedKey, byte[] context);
    }

    record EncapsulatedKey(byte[] encapsulation, State replyState) {}
    record DecapsulatedKey(DataEncapsulationKey key, KeySet sender, State replyState) {}

}
