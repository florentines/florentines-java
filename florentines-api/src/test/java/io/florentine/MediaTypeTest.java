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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

public class MediaTypeTest {

    @DataProvider
    public Object[][] positiveTestCases() {
        return new Object[][] {
                {"application/json", "application", "json", Map.of()},
                {"application/json;charset=utf-8", "application", "json", Map.of("charset", "utf-8")},
                {"image/png; foo=bar;   bar=toast", "image", "png", Map.of("foo", "bar", "bar", "toast")},
                {"application/vnd.foo+json", "application", "vnd.foo+json", Map.of()},
                {"application/test;foo=\"A String With\\\" \\\\Strange Characters\"",
                    "application", "test", Map.of("foo", "A String With\" \\Strange Characters")},
        };
    }

    @Test(dataProvider = "positiveTestCases")
    public void shouldParseValidMediaTypesCorrectly(
            String mediaType, String expectedType, String expectedSubtype, Map<String, String> expectedParams) {
        var parsed = MediaType.parseStrict(mediaType).orElseThrow();
        assertThat(parsed)
                .hasFieldOrPropertyWithValue("type", expectedType)
                .hasFieldOrPropertyWithValue("subtype", expectedSubtype)
                .hasFieldOrPropertyWithValue("params", expectedParams);
    }

    @DataProvider
    public Object[][] negativeTestCases() {
        return new Object[][] {
                {"$/%^"},
                {"$/json"},
                {"application/$"},
                {"application/foo extra stuff"},
                {"application/foo;duplicate=a;DUPLICATE=b"},
                {"application/json;charset=utf-8 extra stuff"},
                {"application/json extra;charset=utf-8"},
        };
    }

    @Test(dataProvider = "negativeTestCases")
    public void shouldRejectInvalidMediaTypes(String invalid) {
        assertThat(MediaType.parseStrict(invalid)).isEmpty();
    }

    @Test
    public void shouldParseStructuredSuffixCorrectly() {
        var parsed = MediaType.parseStrict("application/foo+json").orElseThrow();
        assertThat(parsed.subtypeSuffix()).hasValue("json");
    }

    @Test
    public void shouldParseMissingStructuredSuffixCorrectly() {
        var parsed = MediaType.parseStrict("application/foo").orElseThrow();
        assertThat(parsed.subtypeSuffix()).isEmpty();
    }

    @Test
    public void shouldParseCharsetCorrectly() {
        var parsed = MediaType.parseStrict("application/foo;charset=utf-16").orElseThrow();
        assertThat(parsed.charset()).hasValue(StandardCharsets.UTF_16);
    }

    @Test
    public void shouldDefaultToApplicationType() {
        var parsed = MediaType.parseWithOptionalType("json").orElseThrow();
        assertThat(parsed.type()).isEqualTo("application");
        assertThat(parsed.subtype()).isEqualTo("json");
    }

    @Test
    public void shouldConvertTypeAndSubtypeToLowerCase() {
        var parsed = MediaType.parseStrict("AppLiCaTioN/JsOn").orElseThrow();
        assertThat(parsed.type()).isEqualTo("application");
        assertThat(parsed.subtype()).isEqualTo("json");
    }

    @Test
    public void shouldConvertParameterNamesToLowerCase() {
        var parsed = MediaType.parseStrict("application/json;CharSet=UTF-8;FooBar=whatSit").orElseThrow();
        assertThat(parsed.params())
                .containsOnly(entry("charset", "UTF-8"), entry("foobar", "whatSit"));
    }
    
    @Test
    public void shouldProduceCorrectStringOutput() {
        var params = new LinkedHashMap<String, String>(2);
        params.put("a", "b");
        params.put("c", "d e\" f");
        var mediaType = new MediaType("text", "test", params);
        assertThat(mediaType.toString()).isEqualTo("text/test; a=b; c=\"d e\\\" f\"");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void shouldRejectDuplicateParametersAfterNormalization() {
        new MediaType("text", "test", Map.of("a", "b", "A", "c"));
    }
}