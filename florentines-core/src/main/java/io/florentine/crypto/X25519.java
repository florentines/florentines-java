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

import io.florentine.Utils;
import software.pando.crypto.nacl.CryptoBox;
import software.pando.crypto.nacl.Subtle;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;

final class X25519 {
    private X25519() {}

    static final int PK_SIZE = 32;

    static byte[] compute(PrivateKey privateKey, PublicKey publicKey) {
        return Subtle.scalarMultiplication(privateKey, publicKey);
    }

    static KeyPair generateKeyPair() {
        return CryptoBox.keyPair();
    }

    static byte[] serializePublicKey(PublicKey pk) {
        Utils.checkState("XDH".equalsIgnoreCase(pk.getAlgorithm()), "Public key has wrong algorithm: " + pk.getAlgorithm());
        XECPublicKey xpk = (XECPublicKey) pk;
        return Utils.toUnsignedLittleEndian(xpk.getU(), PK_SIZE);
    }

    static PublicKey deserializePublicKey(byte[] epk) {
        return CryptoBox.publicKey(epk);
    }
}
