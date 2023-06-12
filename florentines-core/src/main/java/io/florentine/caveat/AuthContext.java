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

package io.florentine.caveat;

import java.time.Instant;
import java.util.Map;

import io.florentine.data.SimpleValue;

/**
 * Represents the context in which a request is being authenticated and checked for authorization.
 *
 * @param requestTime the time at which the request was made.
 * @param subjectAttributes attributes describing the subject making the request.
 * @param requestAttributes attributes describing the request itself.
 * @param environmentAttributes attributes describing the context in which the request is made, such as the location.
 */
public record AuthContext(Instant requestTime,
                          Map<String, ? extends SimpleValue> subjectAttributes,
                          Map<String, ? extends SimpleValue> requestAttributes,
                          Map<String, ? extends SimpleValue> environmentAttributes) {
}
