/*
 * Copyright 2022 Neil Madden.
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

package software.pando.florentines;

import java.util.Arrays;

import javax.crypto.SecretKey;

import software.pando.crypto.nacl.ByteSlice;
import software.pando.crypto.nacl.Bytes;
import software.pando.crypto.nacl.Crypto;

/**
 * A pseudorandom function (PRF). PRFs for use in Florentines should be collision resistant even if the attacker knows
 * the key. That is {@code PRF(k, .)} for some well-known key, k, should act like a collision resistant hash function.
 */
interface PRF {
    /**
     * A {@link PRF} based on HMAC-SHA-512-256 (HMAC-SHA-512 truncated to the first 256 bits of output). This PRF
     * provides a 256-bit security level as a MAC and even if the key is known, it provides 256-bit security against
     * collision and preimage attacks.
     */
    PRF HS512 = new PRF() {
        @Override
        public SecretKey key(byte[] keyMaterial, int offset, int length) {
            return Crypto.authKey(ByteSlice.of(keyMaterial, offset, length));
        }

        @Override
        public byte[] compute(SecretKey key, byte[]... blocks) {
            byte[] tag = new byte[32];
            for (byte[] block : blocks) {
                tag = Crypto.auth(key, block);
                key = Crypto.authKey(tag);
            }
            return tag;
        }
    };

    /**
     * Imports the given key material as a secret key suitable for use with this PRF. The key material should not be
     * used for any other function, and should be zeroed out after calling this method.
     *
     * @param keyMaterial the key material. This should be a uniform random byte array of at least 128 bits entropy.
     * @param offset the offset into the byte array at which the key material starts.
     * @param length the length of the key material.
     * @return a PRF secret key.
     * @throws IllegalArgumentException if the key material is not suitable for this PRF.
     */
    SecretKey key(byte[] keyMaterial, int offset, int length);

    /**
     * Imports the given key material as a secret key suitable for use with this PRF. The key material should not be
     * used for any other function, and should be zeroed out after calling this method.
     *
     * @param keyMaterial the key material. This should be a uniform random byte array of at least 128 bits entropy.
     * @return a PRF secret key.
     * @throws IllegalArgumentException if the key material is not suitable for this PRF.
     */
    default SecretKey key(byte[] keyMaterial) {
        return key(keyMaterial, 0, keyMaterial.length);
    }

    /**
     * Computes the PRF output over the given blocks of input data. The PRF ensures that each block is treated
     * independently of any other block. That is, the inputs {@code aa, bb} will produce a different output to the
     * inputs {@code a, abb} or any other combination.
     * <p>
     * <strong>Warning:</strong> The PRF output can be <em>extended</em>, such that additional blocks can be added
     * to the end.
     *
     * @param key the PRF key.
     * @param blocks the blocks of data to authenticate.
     * @return the PRF output tag.
     */
    byte[] compute(SecretKey key, byte[]... blocks);

    /**
     * Verifies that the computed PRF tag over the given input blocks with the given key matches the provided tag.
     *
     * @param key the PRF key.
     * @param providedTag the provided tag to compare against.
     * @param blocks the blocks of data to authenticate.
     * @return {@code true} if the computed tag matches the provided tag, or {@code false} otherwise.
     */
    default boolean verify(SecretKey key, byte[] providedTag, byte[]... blocks) {
        byte[] computedTag = compute(key, blocks);
        try {
            return Bytes.equal(computedTag, providedTag);
        } finally {
            Arrays.fill(computedTag, (byte) 0);
        }
    }
}
