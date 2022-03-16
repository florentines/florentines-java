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

import com.grack.nanojson.JsonObject;

public final class PublicIdentity {

    private final byte[] publicKeyMaterial;
    private final String algorithm;
    private final String application;
    private final String subject;

    public PublicIdentity(byte[] publicKeyMaterial, String algorithm, String application, String subject) {
        this.publicKeyMaterial = publicKeyMaterial;
        this.algorithm = algorithm;
        this.application = application;
        this.subject = subject;
    }

    public byte[] getPublicKeyMaterial() {
        return publicKeyMaterial;
    }

    public String getAlgorithmIdentifier() {
        return algorithm;
    }

    public String getApplication() {
        return application;
    }

    public Optional<String> getSubject() {
        return Optional.ofNullable(subject);
    }

    public Optional<Algorithm> getAlgorithm() {
        return Algorithm.get(algorithm);
    }

    public JsonObject toJson() {
        var builder = JsonObject.builder()
                .value("pub", Base64url.encode(publicKeyMaterial))
                .value("alg", algorithm)
                .value("app", application);
        if (subject != null) {
            builder.value("sub", subject);
        }
        return builder.done();
    }
}
