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

import static java.util.Objects.requireNonNull;

import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Optional;

import javax.security.auth.Destroyable;

abstract class KEM {
    public abstract String identifier();

    abstract KeyPair generateKeyPair();
    abstract State begin(DEM dem, LocalIdentity local, Collection<PublicIdentity> remote);

    interface State extends Destroyable {
        DestroyableSecretKey key();
        EncapsulatedKey encapsulate(byte[] context);
        Optional<DecapsulatedKey> decapsulate(byte[] encapsulatedKey, byte[] context);

        @Override
        void destroy(); // No checked exception, any failures should be logged
    }

    record EncapsulatedKey(byte[] encapsulation, State replyState) {}
    record DecapsulatedKey(DestroyableSecretKey key, PublicIdentity sender, State replyState) {}

    interface Identity {
        String identifier();
        PublicKey publicKey();
    }

    record PublicIdentity(String identifier, PublicKey publicKey) implements Identity {
        PublicIdentity {
            requireNonNull(identifier, "identifier");
            requireNonNull(publicKey, "public key");
        }
    }
    record LocalIdentity(String identifier, Key secretKey, PublicKey publicKey) implements Identity {
        LocalIdentity {
            requireNonNull(identifier, "identifier");
            requireNonNull(secretKey, "secret key");
            requireNonNull(publicKey, "public key");
        }

        PublicIdentity toPublicIdentity() {
            return new PublicIdentity(identifier, publicKey);
        }
    }
}
