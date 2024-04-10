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

package io.florentine.crypto;

import java.util.Optional;

import javax.crypto.SecretKey;

public interface KeyWrapCipher {
    KeyWrapCipher A256SIV_HS512 = new SyntheticIVMode("A256SIV-HS512", new AesCtrCipher(),
            HashFunction.SHA512.asPRF());
    KeyWrapCipher CC20SIV_HS512 = DEM.CC20HS512.asKeyWrapCipher();

    String algorithm();
    byte[] wrap(SecretKey wrapKey, SecretKey keyToWrap, byte[] context);
    Optional<DestroyableSecretKey> unwrap(SecretKey unwrapKey, byte[] wrappedKey, String wrappedKeyAlgorithm, byte[] context);
}
