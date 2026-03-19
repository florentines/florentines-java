/*
 * Copyright 2026 Neil Madden.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * Represents an IANA media type as defined in <a href="https://datatracker.ietf.org/doc/html/rfc2046">RFC 2046</a>
 * and related standards. This implementation always eagerly normalizes type, subtype, and parameter names into
 * lowercase in the {@linkplain Locale#ROOT root locale}.
 *
 * @param type the type of the media type, such as "application" or "text". Case-insensitive.
 * @param subtype the subtype of the media type, such as "json" or "png". Case-insensitive.
 * @param params a map of parameters for the media type, such as the charset. Keys are case-insensitive, values may or
 *               may not be case-insensitive.
 */
public record MediaType(String type, String subtype, Map<String, String> params) {
    public static final MediaType JSON = new MediaType("application", "json");
    public static final MediaType XML_UTF8 = new MediaType("application", "xml", Map.of("charset", "utf-8"));

    private static final String RESTRICTED_NAME_PATTERN = "[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]{0,126}";
    private static final String TOKEN = "[0-9A-Za-z!#$%&'*+.^_`|~-]+";
    private static final String QUOTED_STRING = "\"(?:[^\"\\\\]|\\\\.)*\"";
    private static final String PARAM = "[ \t]*;[ \t]*(" + TOKEN + ")=(" + TOKEN + "|" + QUOTED_STRING + ")";

    private static final Pattern MEDIA_TYPE_START = Pattern.compile(
            "(?:(" + RESTRICTED_NAME_PATTERN + ")/)?(" + RESTRICTED_NAME_PATTERN + ")");

    private static final Pattern PARAM_PATTERN = Pattern.compile("\\G" + PARAM);
    private static final Logger log = LoggerFactory.getLogger(MediaType.class);

    public MediaType {
        // NB: we eagerly normalize the type/subtype and parameter keys to lowercase
        type = requireNonNull(type, "type").toLowerCase(Locale.ROOT);
        subtype = requireNonNull(subtype, "subtype").toLowerCase(Locale.ROOT);
        var paramCopy = new LinkedHashMap<String, String>(params.size());
        params.forEach((key, value) -> {
            if (paramCopy.putIfAbsent(key.toLowerCase(Locale.ROOT), value) != null) {
                throw new IllegalArgumentException("duplicate parameter in mediatype");
            }
        });
        params = Collections.unmodifiableMap(paramCopy);
    }

    /**
     * Constructs a media type with the given type and subtype and no parameters.
     *
     * @param type the type of the media type, such as "application" or "text". Case-insensitive.
     * @param subtype the subtype of the media type, such as "json" or "png". Case-insensitive.
     */
    public MediaType(String type, String subtype) {
        this(type, subtype, Map.of());
    }

    public Optional<String> subtypeSuffix() {
        var idx = subtype.lastIndexOf('+');
        return idx >= 0 ? Optional.of(subtype.substring(idx + 1)) : Optional.empty();
    }

    public Optional<Charset> charset() {
        return Optional.ofNullable(params.get("charset")).map(Charset::forName);
    }

    public static Optional<MediaType> parseWithOptionalType(String mediaType) {
        return parseWithOptionalType(mediaType, "application");
    }

    public static Optional<MediaType> parseWithOptionalType(String mediaType, String defaultType) {
        log.trace("Parsing mediatype {} (default type: {})", mediaType, defaultType);
        var matcher = MEDIA_TYPE_START.matcher(mediaType);
        if (matcher.lookingAt()) {
            var type = matcher.group(1);
            if (type == null) {
                type = defaultType;
            }
            var subtype = matcher.group(2);
            var params = new LinkedHashMap<String, String>();
            matcher.usePattern(PARAM_PATTERN);
            int end = matcher.end();
            while (matcher.find()) {
                end = matcher.end();
                var key = matcher.group(1);
                var val = matcher.group(2);
                if (val.startsWith("\"")) {
                    val = val.substring(1, val.length() - 1).replaceAll("\\\\(.)", "$1");
                }
                if (params.putIfAbsent(key.toLowerCase(Locale.ROOT), val) != null) {
                    log.debug("Mediatype {} has duplicate parameter: {}", mediaType, key);
                    return Optional.empty();
                }
            }
            if (end < mediaType.length()) {
                log.debug("Trailing garbage after mediatype: {} (around char {})", mediaType, end);
                return Optional.empty();
            }
            return Optional.of(new MediaType(type, subtype, params));
        } else {
            log.debug("Media type doesn't match type/subtype format: {}", mediaType);
            return Optional.empty();
        }
    }

    public static Optional<MediaType> parseStrict(String mediaType) {
        return parseWithOptionalType(mediaType, null);
    }

    @Override
    public String toString() {
        var sb = new StringBuilder().append(type).append('/').append(subtype);
        // Apparently some applications error if there isn't a space after the semicolon:
        params.forEach((key, value) -> sb.append("; ").append(key).append('=').append(quoteIfNecessary(value)));
        return sb.toString();
    }

    private static String quoteIfNecessary(String value) {
        return value.matches(TOKEN) ? value : '"' + value.replaceAll("[\"\\\\\n]", "\\\\$0") + '"';
    }
}
