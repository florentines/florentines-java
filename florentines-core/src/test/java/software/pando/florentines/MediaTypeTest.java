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

import static java.util.stream.Collectors.toList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.SoftAssertions.assertSoftly;

import java.util.List;
import java.util.Map;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class MediaTypeTest {

    @DataProvider
    public Object[][] mediaTypes() {
        return new Object[][] {
                { "text/plain ; charset=us-ascii", "text", "plain", Map.of("charset", "us-ascii") },
                { "text/plain ; charset=\"us-asc\\ii\"", "text", "plain", Map.of("charset", "us-ascii") },
                { "text/plain ; charset=\"\\\"us-ascii\\\"\"", "text", "plain", Map.of("charset", "\"us-ascii\"") },
                { "TeXT/PlaIn;CharSet=US-ascii", "text", "plain", Map.of("charset", "US-ascii") },
                { "text/plain ; charset=us-ascii; weight=bold", "text", "plain",
                        Map.of("charset", "us-ascii", "weight", "bold") },
                { "application/json", "application", "json", Map.of() },
                { "*/*", "*", "*", Map.of() },
        };
    }

    @Test(dataProvider = "mediaTypes")
    public void shouldParseMediaTypesCorrectly(String mediaType, String type, String subtype,
            Map<String, String> params) {
        var parsed = MediaType.parse(mediaType).orElseThrow();
        assertSoftly(softly -> {
            softly.assertThat(parsed.getType()).isEqualTo(type);
            softly.assertThat(parsed.getSubtype()).isEqualTo(subtype);
            softly.assertThat(parsed.getParameters()).isEqualTo(params);
        });
    }

    @DataProvider
    public Object[][] matchingTestCases() {
        return new Object[][] {
                { "*/*", "text/plain;charset=UTF-8" },
                { "*/*", "application/octet-stream" },
                { "text/*", "text/html" },
                { "application/json", "application/json;charset=UTF-8" },
                { "application/json", "application/foo+json" },
        };
    }

    @Test(dataProvider = "matchingTestCases")
    public void shouldMatchPatterns(String pattern, String value) {
        MediaType patternType = MediaType.parse(pattern).orElseThrow();
        MediaType valueType = MediaType.parse(value).orElseThrow();
        assertThat(patternType.matches(valueType)).isTrue();
    }

    @Test
    public void shouldOrderPatternsFromMostToLeastSpecific() {
        List<MediaType> patterns = List.of(
                MediaType.parse("text/*").orElseThrow(),
                MediaType.parse("text/plain").orElseThrow(),
                MediaType.parse("text/plain;format=flowed").orElseThrow(),
                MediaType.parse("*/*").orElseThrow());

        List<MediaType> sorted = patterns.stream().sorted(MediaType.PREFERENCE_ORDER).collect(toList());
        assertThat(sorted).containsExactly(
                new MediaType("text", "plain", Map.of("format", "flowed")),
                new MediaType("text", "plain"),
                new MediaType("text", "*"),
                new MediaType("*", "*"));
    }

    @Test
    public void shouldOrderPatternsAccordingToWeight() {
        List<MediaType> patterns = List.of(
                MediaType.parse("text/plain; q=0.5").orElseThrow(),
                MediaType.parse("text/html").orElseThrow(),
                MediaType.parse("text/x-dvi; q=0.8").orElseThrow(),
                MediaType.parse("text/x-c").orElseThrow());

        List<MediaType> sorted = patterns.stream().sorted(MediaType.PREFERENCE_ORDER).collect(toList());
        // The text/html and text/x-c options are equally preferred so can appear in any order, but must be before the
        // other two.
        assertThat(sorted).containsExactlyInAnyOrderElementsOf(patterns).endsWith(
                new MediaType("text", "x-dvi", Map.of("q", "0.8")),
                new MediaType("text", "plain", Map.of("q", "0.5")));
    }
}