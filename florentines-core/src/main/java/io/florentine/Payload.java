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

package io.florentine;

import java.util.EnumSet;

/**
 * Represents a decoded payload from a decrypted Florentine. Each payload can have payload-specific headers, such as
 * a content-type, in addition to the overall headers specified for the Florentine itself.
 *
 * @param headers any payload-specific headers.
 * @param content the content. The format of the content depends on the content-type ("cty") header specified in
 *                either the payload-specific headers or the main Florentine headers.
 * @param flags a set of options describing whether the content is encrypted, compressed, or otherwise transformed in
 *             some way. The details of the compression/encryption algorithm and other options are specified in the
 *              headers (either on this specific payload or in the main Florentine headers). The reason why these
 *              flags are not themselves headers is that the state of the content (reflected by these flags) can vary
 *              during processing, whereas the headers are treated as immutable.
 */
public record Payload(Headers headers, byte[] content, EnumSet<ContentEncoding> flags) {

    /**
     * Flags that indicate any transformations or encodings applied to the content. Only a simple on/off indicator is
     * used at this level, and the details of how the encoding is implemented (algorithm, parameters, etc.) are
     * specified in headers.
     */
    public enum ContentEncoding {
        /**
         * Indicates that the content is encrypted and must be decrypted before it can be accessed.
         */
        ENCRYPTED,
        /**
         * Indicates that the content is compressed.
         */
        COMPRESSED
    }
}
