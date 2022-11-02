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

import static java.util.Objects.requireNonNull;

import java.util.Collection;
import java.util.List;

import javax.crypto.SecretKey;

public final class Florentine {
    // ephemeral key (epk)  - 32 bytes
    // salted sender key id - 4 bytes
    // num_recipients       - 2 bytes
    // for each recipient:
    //      salted key id   - 4 bytes
    //      wrapped data key - 48 bytes (32 byte key + 16 byte SIV)
    // header
    //

    private final Algorithm algorithm;
    private final Header header;

    private SecretKey tag;

    Florentine(Algorithm algorithm, Header header, SecretKey tag) {
        this.algorithm = algorithm;
        this.header = header;
        this.tag = tag;
    }

    public Florentine restrict(byte[] caveat) {
        SecretKey newTag = algorithm.dem.authenticate(tag, caveat).done();
        Utils.destroy(tag);
        this.tag = newTag;
        return this;
    }


    public static class Builder {
        private KeyInfo sender;
        private Collection<KeyInfo> recipients;

        private final Header header = new Header();

        Builder() {
        }

        public Builder from(KeyInfo sender) {
            if (this.sender != null) {
                throw new IllegalStateException("Sender already set");
            }
            this.sender = requireNonNull(sender);
            return this;
        }

        public Builder to(KeyInfo... recipients) {
            return to(List.of(recipients));
        }

        public Builder to(Collection<KeyInfo> recipients) {
            if (requireNonNull(recipients).isEmpty()) {
                throw new IllegalArgumentException("No recipients specified");
            }
            if (this.recipients != null) {
                throw new IllegalStateException("Recipients already set");
            }
            this.recipients = List.copyOf(recipients);
            return this;
        }

        public Builder compression(Compression compression) {
            header.compression(compression);
            return this;
        }

        public Builder contentType(MediaType contentType) {
            header.contentType(contentType);
            return this;
        }
    }
}
