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

package io.florentine.dem;

import io.florentine.Bytes;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

public class DEMTest {

    @DataProvider
    public Object[][] dems() {
        return new Object[][] {
                { "A128SIV-HS256", A128SIVHS256.class },
                { "CC20SIV-HS512", CC20SIVHS512.class },
        };
    }

    @Test(dataProvider = "dems")
    public void shouldReturnCorrectDem(String identifier, Class<? extends DEM> expectedType) {
        var dem = DEM.get(identifier);
        assertThat(dem).containsInstanceOf(expectedType);
    }

    @Test(dataProvider = "dems", enabled = false)
    public void testEncapsulateSpeed(String identifier, Class<?> ignored) {
        var dem = DEM.get(identifier).orElseThrow();
        var key = dem.importKey(Bytes.secureRandom(32));

        var blockSize = 2048;
        var secretData = randomBlocks(100, blockSize);
        var publicData = randomBlocks(100, blockSize);

        // Warmup
        for (int i = 0; i < 1000; ++i) {
            dem.encapsulate(key, publicData, secretData);
        }

        // Measurements
        int iterations = 10_000;
        long start = System.nanoTime();
        for (int i = 0; i < iterations; ++i) {
            dem.encapsulate(key, publicData, secretData);
        }
        long end = System.nanoTime();

        System.out.printf("%s -> %.2fns%n", identifier, (end - start)/(double)iterations);
    }

    private static List<byte[]> randomBlocks(int numBlocks, int blockSize) {
        var random = new Random();
        var blocks = new ArrayList<byte[]>(numBlocks);
        var block = new byte[blockSize];
        for (int i = 0; i < numBlocks; ++i) {
            random.nextBytes(block);
            blocks.add(block.clone());
        }
        return blocks;
    }
}