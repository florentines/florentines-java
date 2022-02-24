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

import com.grack.nanojson.JsonObject;

public final class FlorentinePublicKey {

    private final byte[] publicKeyMaterial;
    private final String algorithm;
    private final String applicationContextString;

    public FlorentinePublicKey(byte[] publicKeyMaterial, String algorithm, String applicationContextString) {
        this.publicKeyMaterial = publicKeyMaterial;
        this.algorithm = algorithm;
        this.applicationContextString = applicationContextString;
    }

    public byte[] getPublicKeyMaterial() {
        return publicKeyMaterial;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getApplicationContextString() {
        return applicationContextString;
    }

    public JsonObject toJson() {
        return JsonObject.builder()
                .value("pub", Base64url.encode(publicKeyMaterial))
                .value("alg", algorithm)
                .value("app", applicationContextString)
                .done();
    }
}
