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

import java.util.Base64;

/**
 * Utilities that provide support for URL-safe Base64 encoding.
 */
public final class Base64url {
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    /**
     * Encodes the given data in a URL-safe base64-encoded string, without any padding characterts.
     *
     * @param data the binary data to encode.
     * @return the URL-safe base64 encoding of the data.
     */
    public static String encode(byte[] data) {
        return ENCODER.encodeToString(data);
    }

    /**
     * Decodes some URL-safe base64-encoded data, returning the decoded data.
     *
     * @param encoded the encoded data to decode.
     * @return the decoded data.
     * @throws IllegalArgumentException if the encoded data is not valid.
     */
    public static byte[] decode(String encoded) {
        return DECODER.decode(encoded);
    }
}
