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

import static org.assertj.core.api.SoftAssertions.assertSoftly;

import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

public class RequireTest {

    @Test
    public void testNotEmpty() {
        assertSoftly(softly -> {
            softly.assertThatIllegalArgumentException()
                    .isThrownBy(() -> Require.notEmpty(List.of(), "test"))
                    .withMessage("test");
            softly.assertThatIllegalArgumentException()
                    .isThrownBy(() -> Require.notEmpty(Collections::emptyIterator, "test"))
                    .withMessage("test");
            softly.assertThatCode(() -> Require.notEmpty(List.of(1), "test"))
                    .doesNotThrowAnyException();
        });
    }
}