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

package io.florentine.data;

import java.io.Closeable;
import java.io.IOException;

public interface DataWriter extends Closeable {
    /** The maximum integer value that can safely be transmitted via JSON. */
    long MAX_SAFE_INTEGER = 9007199254740991L;
    /** The minimum integer value that can safely be transmitted via JSON. */
    long MIN_SAFE_INTEGER = -9007199254740991L;

    void writeBool(boolean b) throws IOException;
    void writeInt(long i) throws IOException;
    void writeNum(double d) throws IOException;
    void writeText(String s) throws IOException;
    void writeBytes(byte[] b) throws IOException;
    void writeRank1Array(Rank1Array array) throws IOException;
    void writeRank1Map(Rank1Map map) throws IOException;
    void writeRank2Array(Rank2Array array) throws IOException;
    void writeRank2Map(Rank2Map map) throws IOException;
}
