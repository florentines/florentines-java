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

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

public class MediaTypeTest {

    @Test
    public void shouldLowerCasePrimaryType() {
        assertThat(MediaType.parse("FoO/bar")).get()
                .hasFieldOrPropertyWithValue("type", "foo");
    }

    @Test
    public void shouldLowerCaseSubType() {
        assertThat(MediaType.parse("foo/bAR")).get()
                .hasFieldOrPropertyWithValue("subtype", "bar");
    }

    @Test
    public void shouldLowerCaseParameterNames() {
        assertThat(MediaType.parse("foo/bar;SomeProperty=xxx")).get()
                .hasFieldOrPropertyWithValue("params", Map.of("someproperty", List.of("xxx")));
    }

    @Test
    public void shouldCollectDuplicateParametersInAppearanceOrder() {
        assertThat(MediaType.parse("foo/bar;Test=a ; tEsT=b; TEST=c;test=d")).get()
                .hasFieldOrPropertyWithValue("params", Map.of("test", List.of("a", "b", "c", "d")));
    }

    @Test
    public void shouldGetFirstPropertyValueWhenPresent() {
        var parsed = MediaType.parse("foo/bar;Test=a ; tEsT=b; TEST=c;test=d").orElseThrow();
        assertThat(parsed.getFirstParam("test")).get().isEqualTo("a");
    }

    @Test
    public void shouldCollectMultipleParameters() {
        assertThat(MediaType.parse("foo/bar;A=aa;B=bb")).get()
                .hasFieldOrPropertyWithValue("params", Map.of("a", List.of("aa"), "b", List.of("bb")));
    }

    @Test
    public void shouldPreserveCaseOfParameterValues() {
        assertThat(MediaType.parse("foo/bar;key=SoMeVaLuE")).get()
                .hasFieldOrPropertyWithValue("params", Map.of("key", List.of("SoMeVaLuE")));
    }

    @Test
    public void shouldParseQuotedStringValues() {
        assertThat(MediaType.parse("foo/bar;key = \"SoMeVaLuE with a \\\" quote\"")).get()
                .hasFieldOrPropertyWithValue("params", Map.of("key", List.of("SoMeVaLuE with a \" quote")));
    }

    @Test
    public void shouldParseCharset() {
        var mediaType = MediaType.parse("foo/bar;charset=utf-8").orElseThrow();
        assertThat(mediaType.getCharset()).get().isEqualTo(StandardCharsets.UTF_8);
    }

    @Test
    public void shouldDefaultToApplicationTypeIfNotSpecified() {
        assertThat(MediaType.parse("florentine")).get()
                .hasFieldOrPropertyWithValue("type", "application")
                .hasFieldOrPropertyWithValue("subtype", "florentine");
    }

    @Test
    public void shouldOmitApplicationPrefixWhenPossible() {
        assertThat(MediaType.of("application", "florentine").toString(true)).isEqualTo("florentine");
    }

    @Test
    public void shouldNotOmitPrefixIfNotApplication() {
        assertThat(MediaType.of("app", "florentine").toString(true)).isEqualTo("app/florentine");
    }

    @Test
    public void shouldNotOmitPrefixIfParameterContainsSlash() {
        assertThat(MediaType.of("application", "florentine", Map.of("x", "some/thing")).toString(true))
                .isEqualTo("application/florentine;x=\"some/thing\""); // Has to be quoted to contain a slash
    }
}