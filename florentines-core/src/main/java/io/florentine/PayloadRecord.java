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

package io.florentine;

import java.util.List;

final class PayloadRecord extends Record {
    private final byte[] content;
    private final byte[] headers;

    PayloadRecord(Headers headers, byte[] content, Flag... flags) {
        super(Type.PAYLOAD, flags);
        this.content = content;
        this.headers = headers.toBytes();
    }

    @Override
    List<byte[]> secretContent() {
        return List.of(headers, content);
    }

    @Override
    byte[] publicRecordContent() {
        return Utils.emptyBytes();
    }
}
