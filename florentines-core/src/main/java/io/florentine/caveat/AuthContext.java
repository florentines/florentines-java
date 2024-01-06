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

import static io.florentine.Utils.rejectIf;
import static io.florentine.Utils.rejectUnless;

import java.time.Instant;
import java.util.Map;

import io.florentine.data.SimpleValue;

/**
 * Represents the context in which a request is being authenticated and checked for authorization. We loosely follow
 * the XACML model, where an authorization decision is based on four sets of attributes:
 * <ul>
 *     <li>Attributes of the <em>subject</em> (user, service, device) making the request.</li>
 *     <li>Attributes about the <em>resource</em> being accessed or manipulated.</li>
 *     <li>Attributes about the <em>request</em> (or <em>action</em>) being performed.</li>
 *     <li>The <em>environment</em> in which the request is being performed, such as the time of day or location of
 *     the server processing the request.</li>
 * </ul>
 *
 * @param subjectAttributes attributes describing the subject making the request. These attributes about the user
 *                          should come from a trusted source after authentication.
 * @param resourceAttributes attributes describing the resource being accessed, such as a file or service. These
 *                           should be trusted attributes about the resource being accessed, typically determined by
 *                           the server performing the authorization decision. Avoid putting user-supplied
 *                           information from the request in this set of attributes.
 * @param requestAttributes attributes describing the request being performed by the subject on the resource. This
 *                          will typically include details of the action or query being performed. For example, for a
 *                          HTTP request this should include the HTTP method, request path, query parameters and so on.
 * @param environmentAttributes attributes describing the context in which the request is made, such as the time.
 */
public record AuthContext(Map<String, ? extends SimpleValue> subjectAttributes,
                          Map<String, ? extends SimpleValue> resourceAttributes,
                          Map<String, ? extends SimpleValue> requestAttributes,
                          Map<String, ? extends SimpleValue> environmentAttributes) {

    /**
     * Environment attribute used for holding the time at which the request is being processed.
     */
    public static final String NOW = "now";

    public AuthContext {
        rejectIf(subjectAttributes == null || resourceAttributes == null || requestAttributes == null ||
                environmentAttributes == null, "null attribute map");
        rejectUnless(environmentAttributes.containsKey(NOW), "environment map must contain 'now' key");
        rejectIf(environmentAttributes.get(NOW).asLong().isEmpty(), "'now' attribute is invalid");
    }

    public Instant time() {
        return environmentAttributes.get(NOW).asInstant().orElseThrow();
    }
}
