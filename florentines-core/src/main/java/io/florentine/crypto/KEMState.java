/*
 * Copyright 2023 Neil Madden.
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

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.util.Optional;

/**
 * Represents the ongoing state maintained by a {@link AnonKEM} or {@link AuthKEM} as messages are processed.
 */
public interface KEMState extends AutoCloseable, Destroyable {

    /**
     * A DEM key to use to encrypt or decrypt a single message. The key must not be used for more than one message.
     *
     * @return the DEM key.
     */
    SecretKey key();

    /**
     * Encapsulates the current state of the KEM and returns it as an opaque sequence of bytes. These bytes can be
     * considered similar to a ciphertext and have at least IND-CCA2 security. The encapsulation is strongly bound to
     * any tag that is passed in as the argument, in the manner of a Tag-KEM. In particular, this is intended to take
     * a <em>compactly-committing</em> DEM tag to ensure insider auth security when sending a message to multiple
     * recipients.
     *
     * @param tag the associated data to integrity protect as part of the encapsulation.
     * @return the encapsulated state.
     */
    byte[] encapsulate(byte[] tag);

    /**
     * Attempts to decapsulate a KEM state that has previously been {@linkplain #encapsulate(byte[]) encapsulated}.
     * The tag provided must exactly match the tag used during encapsulation.
     *
     * @param tag the tag provided during encapsulation.
     * @param encapsulation the encapsulated KEM state.
     * @return the recovered DEM key if successful, otherwise an empty result if decapsulation fails for any reason.
     */
    Optional<SecretKey> decapsulate(byte[] tag, byte[] encapsulation);

    /**
     * Calls {@link #destroy()}, ignoring any errors that are thrown.
     */
    @Override
    default void close() {
        Utils.destroy(this);
    }
}
