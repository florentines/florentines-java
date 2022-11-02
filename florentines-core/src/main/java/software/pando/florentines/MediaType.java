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
import static java.util.stream.Collectors.toUnmodifiableMap;

import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Comparator;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.MatchResult;
import java.util.regex.Pattern;

public final class MediaType {

    public static final Comparator<MediaType> PREFERENCE_ORDER = Comparator.comparingDouble(MediaType::getWeight)
            .thenComparing((a, b) -> {
                if (!isWildcard(a.type) && isWildcard(b.type)) {
                    return 1;
                } else if (isWildcard(a.type) && !isWildcard(b.type)) {
                    return -1;
                } else if (!isWildcard(a.subtype) && isWildcard(b.subtype)) {
                    return 1;
                } else if (isWildcard(a.subtype) && !isWildcard(b.subtype)) {
                    return -1;
                } else {
                    return Integer.compare(a.getParameters().size(), b.getParameters().size());
                }
            })
            .reversed();

    private static final Pattern MEDIA_TYPE_PATTERN;
    private static final Pattern MEDIA_TYPE_PARAMS_PATTERN;
    private static final String TOKEN = "[^\u0000-\u0020()<>@,;:\"\\\\/\\[\\]?=]+";

    static {
        var quotedString = "\"(?:[^\"\r\\\\]|\\\\.)*\"";
        var typeSubtype = "(" + TOKEN + ")/(" + TOKEN + ")";
        var value = "(" + TOKEN + "|" + quotedString + ")";
        var params = "\\s*;\\s*(" + TOKEN + ")=" + value + "";
        MEDIA_TYPE_PATTERN = Pattern.compile(typeSubtype);
        MEDIA_TYPE_PARAMS_PATTERN = Pattern.compile(params);
    }


    private final String type;
    private final String subtype;
    private final Map<String, String> parameters;

    public MediaType(String type, String subtype, Map<String, String> parameters) {
        this.type = requireNonNull(type, "type").toLowerCase(Locale.ROOT);
        this.subtype = requireNonNull(subtype, "subtype").toLowerCase(Locale.ROOT);
        this.parameters = requireNonNull(parameters, "parameters").entrySet().stream()
                .collect(toUnmodifiableMap(entry -> entry.getKey().toLowerCase(Locale.ROOT), Entry::getValue));

        if (isWildcard(type) && !isWildcard(subtype)) {
            throw new IllegalArgumentException("Wildcard type with concrete subtype is not valid");
        }
    }

    public MediaType(String type, String subtype) {
        this(type, subtype, Map.of());
    }

    public static Optional<MediaType> parse(String mediaType) {
        var matcher = MEDIA_TYPE_PATTERN.matcher(mediaType);
        if (matcher.lookingAt()) {
            var type = matcher.group(1);
            var subtype = matcher.group(2);

            var params = matcher.usePattern(MEDIA_TYPE_PARAMS_PATTERN).results()
                    .map(MediaType::processQuotedString)
                    .collect(toUnmodifiableMap(Entry::getKey, Entry::getValue));

            return Optional.of(new MediaType(type, subtype, params));
        }
        return Optional.empty();
    }

    private static Entry<String, String> processQuotedString(MatchResult result) {
        String param = result.group(1);
        String value = result.group(2);
        if (value.startsWith("\"")) {
            value = value.substring(1, value.length() - 1).replaceAll("\\\\(.)", "$1");
        }
        return new SimpleImmutableEntry<>(param, value);
    }

    public String getType() {
        return type;
    }

    public String getSubtype() {
        return subtype;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public double getWeight() {
        double weight = Double.parseDouble(parameters.getOrDefault("q", "1.0"));
        if (Double.isNaN(weight) || weight < 0.0d || weight > 1.0d) {
            return 1.0d;
        }
        return weight;
    }

    public boolean matches(MediaType that) {
        return matches(this.type, that.type) &&
                (matches(this.subtype, that.subtype) || matchesSuffix(this.subtype, that.subtype)) &&
                that.parameters.entrySet().containsAll(this.parameters.entrySet());
    }

    private static boolean matches(String pattern, String value) {
        return isWildcard(pattern) || pattern.equals(value);
    }

    private static boolean matchesSuffix(String pattern, String value) {
        int index = value.indexOf('+');
        if (index >= 0) {
            return pattern.equals(value.substring(index + 1));
        }
        return false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof MediaType)) {
            return false;
        }
        MediaType mediaType = (MediaType) o;
        return type.equals(mediaType.type) && subtype.equals(mediaType.subtype) && parameters.equals(mediaType.parameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, subtype, parameters);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder().append(type).append('/').append(subtype);
        if (!parameters.isEmpty()) {
            parameters.forEach((key, value) -> {
                sb.append(';').append(key).append('=');
                if (needsQuoting(value)) {
                    sb.append('"').append(value.replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
                } else {
                    sb.append(value);
                }
            });
        }
        return sb.toString();
    }

    private static boolean isWildcard(String value) {
        return "*".equals(value);
    }

    private static boolean needsQuoting(String value) {
        return !value.matches(TOKEN);
    }
}
