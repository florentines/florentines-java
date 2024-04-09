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

import java.util.List;
import java.util.Optional;

import javax.crypto.SecretKey;

public interface DEM {
    DEM CC20HS512 = io.florentine.crypto.CC20HS512.INSTANCE;

    default String identifier() {
        return cipher().identifier() + "-" + prf().identifier();
    }

    DestroyableSecretKey importKey(byte[] keyMaterial);
    CaveatKeyAndTag encrypt(SecretKey key, List<? extends Part> parts);
    Optional<DestroyableSecretKey> decrypt(SecretKey key, List<? extends Part> parts, byte[] expectedTag);

    PRF prf();
    StreamCipher cipher();

    default KeyWrapCipher asKeyWrapCipher() {
        return new SyntheticIVMode(identifier().replaceAll("(CTR)?-", "SIV-"), cipher(), prf());
    }

    record CaveatKeyAndTag(DestroyableSecretKey caveatKey, byte[] tag) {}

    interface Part {
        byte[] content();
        byte[] header();
        boolean isEncrypted();
    }
}
