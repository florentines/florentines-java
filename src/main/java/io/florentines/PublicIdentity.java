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

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import com.grack.nanojson.JsonObject;

public final class PublicIdentity {

    private final byte[] publicKeyMaterial;
    private final String algorithm;
    private final String application;
    private final String id;

    public PublicIdentity(byte[] publicKeyMaterial, String algorithm, String application, String id) {
        this.publicKeyMaterial = publicKeyMaterial;
        this.algorithm = algorithm;
        this.application = application;
        this.id = id;
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

    public String getId() {
        return id;
    }

    public Optional<Algorithm> getAlgorithm() {
        return Algorithm.get(algorithm);
    }

    public JsonObject toJson() {
        return JsonObject.builder()
                .value("pub", Base64url.encode(publicKeyMaterial))
                .value("alg", algorithm)
                .value("app", application)
                .value("id", id)
                .done();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        PublicIdentity that = (PublicIdentity) o;
        return Arrays.equals(publicKeyMaterial, that.publicKeyMaterial) &&
                Objects.equals(algorithm, that.algorithm) &&
                Objects.equals(application, that.application) &&
                Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(algorithm, application, id);
        result = 31 * result + Arrays.hashCode(publicKeyMaterial);
        return result;
    }

    @Override
    public String toString() {
        return "PublicIdentity{algorithm='" + algorithm + '\'' + ", application='" + application + '\'' + ", id='" + id + "'}";
    }
}
