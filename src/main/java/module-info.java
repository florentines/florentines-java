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

/**
 * Reference implementation of the {@link io.florentines.Florentine} auth token format.
 */
module io.florentines {
    exports io.florentines;
    exports io.florentines.caveat;

    requires com.grack.nanojson;
    requires co.nstant.in.cbor;
    requires org.slf4j;
    requires software.pando.crypto.nacl;
}