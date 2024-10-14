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

import static java.util.Collections.unmodifiableMap;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toList;

import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

public final class MediaType {
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
    private final Map<String, List<String>> params;

    private MediaType(String type, String subtype, Map<String, List<String>> params) {
        this.type = Require.notBlank(type, "type").toLowerCase(Locale.ROOT).trim();
        this.subtype = Require.notBlank(subtype, "subtype").toLowerCase(Locale.ROOT).trim();
        var copy = new LinkedHashMap<String, List<String>>(params.size());
        params.forEach((key, values) -> copy.put(key, List.copyOf(values)));
        this.params = unmodifiableMap(copy);
    }

    public static MediaType of(String type, String subtype, Map<String, String> params) {
        var newParams = params.entrySet().stream()
                .collect(groupingBy(Map.Entry::getKey,
                        mapping(Map.Entry::getValue, toList())));
        return new MediaType(type, subtype, newParams);
    }

    public static MediaType of(String type, String subtype) {
        return new MediaType(type, subtype, Map.of());
    }

    public static MediaType of(String type, String subtype, String... params) {
        Require.even(params.length, "Params must be key value pairs");
        var paramMap = new LinkedHashMap<String, List<String>>(params.length / 2);
        for (int i = 0; i < params.length; i += 2) {
            paramMap.computeIfAbsent(params[i], k -> new ArrayList<>(1)).add(params[i + 1]);
        }
        return new MediaType(type, subtype, paramMap);
    }

    public static Optional<MediaType> parse(String mediaType) {
        var matcher = MEDIA_TYPE.matcher(mediaType);
        if (matcher.lookingAt()) {
            var type = matcher.group(1);
            if (type == null) {
                type = "application";
            } else {
                type = type.substring(0, type.length() - 1); // Remove trailing /
            }
            var subtype = matcher.group(2);
            var params = new LinkedHashMap<String, List<String>>();
            matcher = PARAMS.matcher(mediaType.substring(matcher.end()));
            while (matcher.find()) {
                var name = matcher.group(1).toLowerCase(Locale.ROOT).trim();
                var value = unquote(matcher.group(2));
                params.computeIfAbsent(name, k -> new ArrayList<>(1)).add(value);
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

    public Map<String, List<String>> getParams() {
        return params;
    }

    public Optional<String> getFirstParam(String name) {
        return params.getOrDefault(name, List.of()).stream().findFirst();
    }

    public Optional<Charset> getCharset() {
        return getFirstParam("charset").flatMap(cs -> {
            try {
                return Optional.of(Charset.forName(cs));
            } catch (UnsupportedCharsetException e) {
                return Optional.empty();
            }
        });
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
        params.forEach((key, values) -> {
            for (var value : values) {
                sb.append(';').append(key).append('=');
                if (value.matches(TOKEN)) {
                    sb.append(value);
                } else {
                    sb.append(quoted(value));
                }
            }
        });
        return sb.toString();
    }

    private boolean cannotOmitApplicationPrefix() {
        // We can only omit the application/ prefix if no parameter values contain a / character
        return params.values().stream().anyMatch(xs -> xs.stream().anyMatch(x -> x.contains("/")));
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
}
