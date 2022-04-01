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

import java.util.Optional;

import javax.crypto.SecretKey;

/**
 * Interface to be implemented by Key Encapsulation Mechanisms (KEMs). A KEM is responsible for generating fresh
 * random encryption keys for a {@link DEM} and also producing an <em>encapsulation</em> of that random key that can
 * be used by recipients to recover the same DEM key for decryption. Florentine KEMs must satisfy the following
 * properties:
 * <ul>
 *     <li>Authentication of both the sender and the recipient(s). The sender should be assured that only the
 *     intended recipients can decrypt the message, and the recipients are assured that only the sender could have
 *     produced the message. The security properties required for Florentines are strong:</li>
 *     <ul>
 *         <li>If {@link #authDecap(ConversationState, byte[], byte[])} returns with a result, then authentication
 *         is guaranteed. Florentine KEMs are not allowed to perform implicit authentication, in which
 *         authentication failures are only later discovered when DEM decryption fails.</li>
 *         <li>The encapsulation process commits to the (compactly committing) DEM authentication tag, ensuring
 *         that other recipients of a Florentine are not able to use the shared DEM key to produce a Florentine
 *         that appears to come from the original sender. Florentines therefore have <em>insider auth security</em>.
 *         This can also be termed <em>insider non-repudiation</em>.</li>
 *     </ul>
 *     <li>Efficient encapsulation of a DEM key for multiple recipients.</li>
 *     <li>The ability to reply to a previously received Florentine. Replies must ensure forward secrecy of
 *     encrypted data (original messages do not have this property).</li>
 * </ul>
 */
interface KEM {

    /**
     * A unique identifier for this KEM algorithm. This string should be chosen so that the likelihood of a collision
     * with another KEM algorithm is minimised.
     *
     * @return a unique idenfifier for this KEM algorithm.
     */
    String getIdentifier();

    /**
     * Generates secret key material and a public identifier for a given party.
     *
     * @param application the application or protocol for which the key is intended to be used. This must be
     *                    specified, and all parties in a Florentine conversation must use the same application
     *                    identifier.
     * @param subject an optional identifier for the particular subject that owns this key. This may be null if the
     *                subject is intended to be anonymous.
     * @return a freshly generated KEM key.
     */
    PrivateIdentity generateKeys(String application, String subject);

    /**
     * Begins a conversation between the given local party and the given set of remote parties. This method should be
     * called either before sending a new message from the local party to the given remote parties, or when receiving
     * a message from one of the given remote parties that is not a reply to a previous message.
     *
     * @param localParty the local party.
     * @param remoteParties one or more remote parties.
     * @return an object that encapsulates the state of the conversation between the given parties.
     */
    ConversationState begin(PrivateIdentity localParty, PublicIdentity... remoteParties);

    /**
     * Returns a DEM key that can be used to encrypt a single message for the given conversation.
     *
     * @param state the conversation state object.
     * @return a fresh DEM key that can be used to encrypt a single message.
     */
    SecretKey demKey(ConversationState state);

    /**
     * Encapsulates the current DEM key for a conversation to all remote parties, authenticating the local party and
     * including the provided tag as additional authenticated data.
     *
     * @param state the conversation state.
     * @param tag the DEM authentication tag to included in the KEM authentication data.
     * @return a pair of a new conversation state, which can be used to process any replies, and the encapsulated DEM
     * key.
     */
    Pair<ConversationState, EncapsulatedKey> authEncap(ConversationState state, byte[] tag);

    /**
     * Decapsulates and verifies the DEM key for a given conversation.
     *
     * @param state the current conversation state.
     * @param encapKey the encapsulated key received from a remote party.
     * @param tag the DEM authentication tag for the received message.
     * @return if authentication succeeds, then a pair of a new conversation state (for sending any reply) and the
     * decapsulated DEM key, otherwise an empty result.
     */
    Optional<Pair<ConversationState, SecretKey>> authDecap(ConversationState state, byte[] encapKey, byte[] tag);
}
