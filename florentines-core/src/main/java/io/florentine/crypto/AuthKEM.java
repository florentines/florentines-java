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

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;

/**
 * An authenticated Key Encapsulation Mechanism (KEM). KEMs in Florentines provide authentication of both the sender
 * and recipient. They support multiple recipients, with <em>insider auth security:</em> legitimate recipients of a
 * message cannot create a new message that appears to come from the original sender.
 */
public interface AuthKEM {
    AuthKEM X25519_A256SIV_HS512 = new X25519AuthKEM(DEM.A256SIV_HS512);

    String getAlgorithmIdentifier();
    KeyPair generateKeyPair();
    KEMState begin(KeyPair local, List<PublicKey> remotes, byte[] context);
}
