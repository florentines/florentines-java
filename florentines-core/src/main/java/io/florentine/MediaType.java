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

import static java.util.Objects.requireNonNull;

import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * A class that represents an internet
 * <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/MIME_types">Media Type</a> (also known as a MIME Type).
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6838">RFC 6838</a>.
 */
public final class MediaType {
    /**
     * Constant for the media type {@code application/json;charset=utf-8}. Although UTF-8 is the default charset, other
     * charsets have been used in the past and charset confusion can lead to information leakage. Use
     * {@link #JSON_WITHOUT_CHARSET} if this causes problems.
     * @see
     * <a href="https://portswigger.net/research/json-hijacking-for-the-modern-web">JSON Hijacking for the Modern Web</a>
     */
    public static final MediaType JSON = MediaType.of("application", "json", Map.of("charset", "utf-8"));
    /**
     * Constant for the media type {@code application/json}. This version does not explicitly specify the UTF-8 charset.
     * For most cases, {@link #JSON} should be used instead.
     */
    public static final MediaType JSON_WITHOUT_CHARSET = JSON.withoutParams();

    // https://www.rfc-editor.org/rfc/rfc6838#section-4.2
    private static final String RESTRICTED_NAME = "[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]{0,126}";
    private static final String TYPE_SUBTYPE = "\\s*(" + RESTRICTED_NAME + "\\s*/)?\\s*(" + RESTRICTED_NAME + ")";
    private static final String TOKEN = "[a-zA-Z0-9!#$%&'*+.^_`{|}~-]+";
    private static final String QUOTED_STRING = "\"(?:[^\"\n\\\\]|\\\\.)*\"";
    private static final String PARAMETER = "(" + TOKEN + ")\\s*=\\s*(" + TOKEN + "|" + QUOTED_STRING + ")";
    private static final Pattern PARAMS = Pattern.compile("\\s*;\\s*" + PARAMETER);
    private static final Pattern MEDIA_TYPE = Pattern.compile(TYPE_SUBTYPE);

    private final String type;
    private final String subtype;
    private final Map<String, String> params;

    private MediaType(String type, String subtype, Map<String, String> params) {
        this.type = Require.notBlank(type, "type").toLowerCase(Locale.ROOT).trim();
        this.subtype = Require.notBlank(subtype, "subtype").toLowerCase(Locale.ROOT).trim();
        this.params = Map.copyOf(params);
    }

    public static MediaType of(String type, String subtype, Map<String, String> params) {
        return new MediaType(type, subtype, params);
    }

    public static MediaType of(String type, String subtype) {
        return new MediaType(type, subtype, Map.of());
    }

    public static MediaType of(String type, String subtype, String... params) {
        Require.even(params.length, "Params must be key value pairs");
        var paramMap = new LinkedHashMap<String, String>(params.length / 2);
        for (int i = 0; i < params.length; i += 2) {
            if (paramMap.putIfAbsent(params[i], params[i + 1]) != null) {
                throw new IllegalArgumentException("Duplicate parameter");
            }
        }
        return new MediaType(type, subtype, paramMap);
    }

    public static Optional<MediaType> parse(String mediaType) {
        if (mediaType == null) {
            return Optional.empty();
        }
        var matcher = MEDIA_TYPE.matcher(mediaType);
        if (matcher.lookingAt()) {
            var type = matcher.group(1);
            if (type == null) {
                type = "application";
            } else {
                type = type.substring(0, type.length() - 1); // Remove trailing /
            }
            var subtype = matcher.group(2);
            var params = new LinkedHashMap<String, String>();
            matcher = PARAMS.matcher(mediaType.substring(matcher.end()));
            while (matcher.find()) {
                var name = matcher.group(1).toLowerCase(Locale.ROOT).trim();
                var value = unquote(matcher.group(2));
                if (params.putIfAbsent(name, value) != null) {
                    return Optional.empty();
                }
            }
            return Optional.of(new MediaType(type, subtype, params));
        } else {
            return Optional.empty();
        }
    }

    private static String unquote(String value) {
        if (!value.startsWith("\"")) {
            return value;
        }
        return value.substring(1, value.length() - 1).replaceAll("\\\\(.)", "$1");
    }

    public String getType() {
        return type;
    }

    public String getSubtype() {
        return subtype;
    }

    public Map<String, String> getParams() {
        return params;
    }

    public Optional<String> getParam(String name) {
        return Optional.ofNullable(params.get(name.toLowerCase(Locale.ROOT)));
    }

    public Optional<Charset> getCharset() {
        return getParam("charset").flatMap(cs -> {
            try {
                return Optional.of(Charset.forName(cs));
            } catch (UnsupportedCharsetException e) {
                return Optional.empty();
            }
        });
    }

    public Optional<MediaType> getSuffixType() {
        var idx = subtype.lastIndexOf('+');
        if (idx == -1 || subtype.endsWith("+")) { return Optional.empty(); }
        return Optional.of(new MediaType(type, subtype.substring(idx + 1), params));
    }

    public MediaType withoutParams() {
        if (params.isEmpty()) { return this; }
        return new MediaType(type, subtype, Map.of());
    }

    @Override
    public String toString() {
        return toString(false);
    }

    String toString(boolean omitApplicationPrefix) {
        var sb = new StringBuilder();
        if (!omitApplicationPrefix || !"application".equals(type) || cannotOmitApplicationPrefix()) {
            sb.append(type).append('/');
        }
        sb.append(subtype);
        params.forEach((key, value) -> {
            sb.append(';').append(key).append('=');
            if (value.matches(TOKEN)) {
                sb.append(value);
            } else {
                sb.append(quoted(value));
            }
        });
        return sb.toString();
    }

    private boolean cannotOmitApplicationPrefix() {
        // We can only omit the application/ prefix if no parameter values contain a / character
        return params.values().stream().anyMatch(x -> x.contains("/"));
    }

    private static String quoted(String value) {
        return '"' + value.replaceAll("[\"\\\\]", "\\\\$0") + '"';
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof MediaType that)) {
            return false;
        }
        return Objects.equals(type, that.type) && Objects.equals(subtype, that.subtype) && Objects.equals(params, that.params);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, subtype, params);
    }

    public Optional<MatchType> matches(MediaType pattern) {
        requireNonNull(pattern);
        MatchType result;

        // Primary type
        if (pattern.getType().equals("*")) {
            result = MatchType.WILDCARD;
        } else if (pattern.getType().equals(this.getType())) {
            result = MatchType.EXACT;
        } else {
            return Optional.empty();
        }

        // Subtype
        if (pattern.getSubtype().equals("*")) {
            result = MatchType.WILDCARD;
        } else if (result == MatchType.WILDCARD) {
            // */foo is invalid
            throw new IllegalArgumentException("Invalid wildcards");
        } else if (pattern.getSubtype().equals(this.getSubtype())) {
            // Result unchanged
        } else if (getSuffixType().flatMap(st -> st.matches(pattern)).isPresent()) {
            result = MatchType.SUFFIX;
        } else {
            return Optional.empty();
        }

        // Parameters
        for (var entry : pattern.params.entrySet()) {
            var value = this.params.get(entry.getKey());
            if (value == null || !value.equals(entry.getValue())) {
                return Optional.empty();
            }
        }

        return Optional.of(result);
    }

    /**
     * Indicates how well the media type {@linkplain #matches(MediaType) matched} a given pattern.
     */
    public enum MatchType {
        /**
         * The media type was an exact match in all aspects.
         */
        EXACT,
        /**
         * The media type matched wildcards in the pattern. For example, if the pattern was {@code application/*} and
         * the media type was {@code application/xml}, then this would result in a wildcard match.
         */
        WILDCARD,
        /**
         * The media type matched due to a suffix. For example, {@code application/foo+xml} would match
         * {@code application/xml}. This match type takes precedence over a wildcard match.
         */
        SUFFIX
    }
}
