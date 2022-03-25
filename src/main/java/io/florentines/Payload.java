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

import java.util.List;

public final class Payload {
    private final Header header;
    private final List<byte[]> contents;

    Payload(Header header, List<byte[]> contents) {
        this.header = header;
        this.contents = List.copyOf(contents);
    }

    public Header header() {
        return header;
    }

    public List<byte[]> contents() {
        return contents;
    }
}
