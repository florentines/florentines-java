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

import static io.florentine.MediaType.MatchType.EXACT;
import static io.florentine.MediaType.MatchType.SUFFIX;
import static io.florentine.MediaType.MatchType.WILDCARD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class MediaTypeTest {

    @Test
    public void shouldNotParseEmptyString() {
        assertThat(MediaType.parse("")).isEmpty();
    }

    @Test
    public void shouldNotParseInvalidValues() {
        // Wildcards can be constructed manually, but are not valid mediatypes themselves
        assertThat(MediaType.parse("*/*")).isEmpty();
    }

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
                .hasFieldOrPropertyWithValue("params", Map.of("someproperty", "xxx"));
    }

    @Test
    public void shouldRejectDuplicateParameters() {
        assertThat(MediaType.parse("foo/bar;Test=a ; tEsT=b; TEST=c;test=d")).isEmpty();
    }

    @Test
    public void shouldGetPropertyValueWhenPresent() {
        var parsed = MediaType.parse("foo/bar;Test=a").orElseThrow();
        assertThat(parsed.getParam("tEst")).get().isEqualTo("a");
    }

    @Test
    public void shouldCollectMultipleParameters() {
        assertThat(MediaType.parse("foo/bar;A=aa;B=bb")).get()
                .hasFieldOrPropertyWithValue("params", Map.of("a", "aa", "b", "bb"));
    }

    @Test
    public void shouldPreserveCaseOfParameterValues() {
        assertThat(MediaType.parse("foo/bar;key=SoMeVaLuE")).get()
                .hasFieldOrPropertyWithValue("params", Map.of("key", "SoMeVaLuE"));
    }

    @Test
    public void shouldParseQuotedStringValues() {
        assertThat(MediaType.parse("foo/bar;key = \"SoMeVaLuE with a \\\" quote\"")).get()
                .hasFieldOrPropertyWithValue("params", Map.of("key", "SoMeVaLuE with a \" quote"));
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

    @Test
    public void shouldReturnCorrectSuffixType() {
        var specific = MediaType.parse("application/foobar+xml;charset=utf-8").orElseThrow();
        assertThat(specific.getSuffixType()).get().asString().isEqualTo("application/xml;charset=utf-8");
    }

    @Test
    public void shouldReturnEmptyIfNoSuffix() {
        var specific = MediaType.parse("application/foobar;charset=utf-8").orElseThrow();
        assertThat(specific.getSuffixType()).isEmpty();
    }

    @Test
    public void shouldRejectInvalidWildCards() {
        var type = MediaType.of("application", "test");
        var pattern = MediaType.of("*", "test");
        assertThatThrownBy(() -> type.matches(pattern)).isInstanceOf(IllegalArgumentException.class);
    }

    @DataProvider
    public Object[][] matchesTests() {
        return new Object[][]{
                {MediaType.of("application", "test"), MediaType.of("application", "test"), Optional.of(EXACT)},
                {MediaType.of("application", "test"), MediaType.of("application", "*"), Optional.of(WILDCARD)},
                {MediaType.of("application", "test"), MediaType.of("*", "*"), Optional.of(WILDCARD)},
                {MediaType.of("application", "test+xml"), MediaType.of("application", "xml"), Optional.of(SUFFIX)},
                {MediaType.of("application", "test", "a", "b"), MediaType.of("application", "test"),
                        Optional.of(EXACT)},
                {MediaType.of("application", "test", "a", "b", "c", "d"), MediaType.of("application", "test", "c", "d"),
                        Optional.of(EXACT)},
                {MediaType.of("application", "test"), MediaType.of("image", "test"), Optional.empty()},
                {MediaType.of("application", "test"), MediaType.of("application", "other"), Optional.empty()},
                {MediaType.of("application", "test", "a", "b"), MediaType.of("application", "test", "a", "c"),
                        Optional.empty()},
                {MediaType.of("application", "test", "c", "d"), MediaType.of("application", "test", "a", "b"),
                        Optional.empty()},

        };
    }

    @Test(dataProvider = "matchesTests")
    public void shouldMatchCorrectly(MediaType type, MediaType pattern, Optional<MediaType.MatchType> expected) {
        assertThat(type.matches(pattern)).isEqualTo(expected);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void shouldRejectDuplicateParams() {
        MediaType.of("test", "test", "a", "b", "a", "c");
    }
}