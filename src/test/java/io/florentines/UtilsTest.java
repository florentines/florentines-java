/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package io.florentines;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.concurrent.ThreadLocalRandom;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class UtilsTest {

    @DataProvider
    public Iterator<BigInteger> randomInts() {
        return ThreadLocalRandom.current().longs(100, 0, Long.MAX_VALUE).mapToObj(BigInteger::valueOf).iterator();
    }

    @Test(dataProvider = "randomInts")
    public void shouldRecreateSameBigInteger(BigInteger value) {
        byte[] le = Utils.toUnsignedLittleEndian(value, 32);
        var result = Utils.fromUnsignedLittleEndian(le);
        assertThat(result).isEqualTo(value);
    }

    @Test(dataProvider = "randomInts")
    public void shouldPadToGivenLength(BigInteger value) {
        byte[] le = Utils.toUnsignedLittleEndian(value, 20);
        assertThat(le).hasSize(20);
    }

    @DataProvider
    public Object[][] reverseTests() {
        return new Object[][] {
                { new byte[0], new byte[0] },
                { new byte[] { 0 }, new byte[] { 0 } },
                { new byte[] { 0, 1 }, new byte[] { 1, 0 } },
                { new byte[] { 0, 1, 2 }, new byte[] { 2, 1, 0} }
        };
    }
    @Test(dataProvider = "reverseTests")
    public void shouldReverseCorrectly(byte[] original, byte[] reversed) {
        Utils.reverse(original);
        assertThat(original).isEqualTo(reversed);
    }

}