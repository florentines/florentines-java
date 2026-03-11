/*
 * Copyright 2026 Neil Madden.
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

package io.florentine.dem;

import io.florentine.crypto.Blake2bPRF;
import io.florentine.crypto.JcaStreamCipher;

final class CC20SIVB2512 extends SyntheticIVMode {
    static final DEM INSTANCE = new CC20SIVB2512();

    private CC20SIVB2512() {
        super(DEM.CC20SIV_B2512, Blake2bPRF.B2512, JcaStreamCipher.CC20);
    }
}
