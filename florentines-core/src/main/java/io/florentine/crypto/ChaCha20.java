/*
 * Copyright 2025 Neil Madden.
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

import javax.crypto.spec.ChaCha20ParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public final class ChaCha20 extends JcaStreamCipher {
    public ChaCha20() {
        super("ChaCha20");
    }

    @Override
    AlgorithmParameterSpec iv(byte[] nonce) {
        return new ChaCha20ParameterSpec(Arrays.copyOf(nonce, 12), 0);
    }
}
