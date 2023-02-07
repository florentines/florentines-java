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

package io.florentine.crypto;

import io.florentine.Utils;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class UtilsTest {

    @DataProvider
    public Object[][] reverseTestCases() {
        return new Object[][] {
                { new byte[0], new byte[0] },
                { new byte[] { 42 }, new byte[] { 42 } },
                { new byte[] { 1, 2 }, new byte[] { 2, 1} },
                { new byte[] { 1, 2, 3 }, new byte[] { 3, 2, 1 } },
        };
    }

    @Test(dataProvider = "reverseTestCases")
    public void testReverse(byte[] original, byte[] reversed) {
        assertThat(Utils.reverseInPlace(original.clone())).isEqualTo(reversed);
        assertThat(Utils.reverseInPlace(reversed.clone())).isEqualTo(original);
    }

    @DataProvider
    public Object[][] littleEndianTestCases() {
        return new Object[][] {
                { BigInteger.ZERO, new byte[32] },
                { BigInteger.ONE, new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
                { BigInteger.valueOf(42),
                        new byte[] { 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
                { BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE),
                        new byte[] { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                     -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 } },
                // NB: this will be interpreted as 255 (unsigned)
                { BigInteger.valueOf(-1), new byte[] { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
        };
    }

    @Test(dataProvider = "littleEndianTestCases")
    public void testToLittleEndian(BigInteger val, byte[] littleEndian) {
        assertThat(Utils.toUnsignedLittleEndian(val, 32)).isEqualTo(littleEndian);
    }

    @DataProvider
    public Object[][] concatTestCases() {
        return new Object[][] {
                { new byte[0], new byte[0] },
                { new byte[0], new byte[0], new byte[0] },
                { new byte[0], new byte[0], new byte[0], new byte[0] },
                { new byte[] { 42 }, new byte[] { 42 }, new byte[0], new byte[0] },
                { new byte[] { 42 }, new byte[0], new byte[] { 42 }, new byte[0] },
                { new byte[] { 42 }, new byte[0], new byte[0], new byte[] { 42 } },
                { new byte[] { 1, 2, 3 }, new byte[] { 1 }, new byte[] { 2 }, new byte[] { 3 } },
                { new byte[] { 1, 2, 3 }, new byte[0], new byte[0], new byte[] { 1, 2, 3 } },
                { new byte[] { 1, 2, 3 }, new byte[0], new byte[] { 1, 2 }, new byte[] { 3 } },
                { new byte[] { 1, 2, 3 }, new byte[] { 1, 2 }, new byte[] { 3 }, new byte[0] },
                { new byte[] { 1, 2, 3 }, new byte[] { 1 }, new byte[0], new byte[] { 2, 3 } },
        };
    }

    @Test(dataProvider = "concatTestCases")
    public void testConcat(byte[] concatenation, byte[]... components) {
        assertThat(Utils.concat(components)).isEqualTo(concatenation);
    }

    @Test
    public void testDestroyIgnoresExceptions() throws Exception {
        var key1 = mock(Destroyable.class);
        var key2 = mock(Destroyable.class);
        doThrow(DestroyFailedException.class).when(key1).destroy();

        Utils.destroy(key1, key2);

        verify(key2).destroy();
    }
}