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

import java.util.Objects;

public enum Compression {
    NONE(null),
    DEFLATE("def");

    final String identifier;

    Compression(String identifier) {
        this.identifier = identifier;
    }

    public static Compression of(String value) {
        for (Compression candidate : values()) {
            if (Objects.equals(value, candidate.identifier)) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("Unknown compression algorithm: " + value);
    }
}
