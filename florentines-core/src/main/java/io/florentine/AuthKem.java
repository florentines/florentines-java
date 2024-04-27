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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Optional;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * An authenticated Key Encapsulation Mechanism (KEM). KEMs used by Florentines have several additional properties:
 *
 */
interface AuthKem {

    KeyPair generateKeyPair();

    /**
     * Begins a process of encapsulating or decapsulating keys using this KEM.
     *
     * @param localParty the local key pair used for encapsulation or decapsulation.
     * @param remoteParties the public keys of any other parties involved in the conversation.
     * @return a {@link KemState} object that can be used to perform further operations.
     */
    KemState begin(LocalParty localParty, Collection<RemoteParty> remoteParties);

    /**
     * Represents the state of the KEM at a given point in time.
     */
    interface KemState extends Destroyable {
        /**
         * Returns a secret key that can be used to encrypt a single message.
         * It is an error to call this method more than once on the same KemState object.
         *
         * @return the encryption key to encrypt a message.
         */
        DestroyableSecretKey key();

        /**
         * Encapsulates the current encryption key.
         *
         * @param context any context arguments to include as associated data. All context arguments will be cryptographically
         *                bound to the encapsulated key.
         * @return the encapsulated key and reply state.
         */
        KeyEncapsulation encapsulate(byte[] context);

        /**
         * Attempts to decapsulate the given encapsulated key with the given context (associated data). If the process succeeds
         * then the decapsulated key and reply state are returned, otherwise an empty result is returned. It is intentional that
         * no details are revealed if decapsulation fails for any reason.
         *
         * @param encapsulatedKey the encapsulated key to decrypt.
         * @param context any associated data. This must match exactly any arguments given to {@link #encapsulate(byte[])} when
         *                the key was encapsulated.
         * @return the decapsulated key and reply state, or an empty result if the key was not valid.
         */
        Optional<KeyDecapsulation> decapsulate(byte[] encapsulatedKey, byte[] context);

        int writeTo(OutputStream out) throws IOException;

        default byte[] toByteArray() {
            try (var out = new ByteArrayOutputStream()) {
                writeTo(out);
                return out.toByteArray();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    record KeyEncapsulation(KemState replyState, byte[] encapsulatedKey) implements Destroyable {

        @Override
        public void destroy() throws DestroyFailedException {
            CryptoUtils.wipe(encapsulatedKey);
            replyState.destroy();
        }

        @Override
        public boolean isDestroyed() {
            return replyState.isDestroyed();
        }
    }

    record KeyDecapsulation(KemState replyState, DestroyableSecretKey decryptionKey) implements Destroyable {

        @Override
        public void destroy() throws DestroyFailedException {
            decryptionKey.destroy();
            replyState.destroy();
        }

        @Override
        public boolean isDestroyed() {
            return decryptionKey.isDestroyed() || replyState.isDestroyed();
        }
    }

}
