/*
 * Copyright 2025 Neil Madden.
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

import org.assertj.core.api.Assertions;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;

import static org.testng.Assert.*;

public class CommittingDEMTest {

    static ECPublicKey x963UncompressedFormatToECPublicKey(String curveName, byte[] key)  {
        try {
            if (key[0] != 0x04) {
                throw new IllegalArgumentException("Invalid key format, expected uncompressed key");
            }
            byte[] rawBytes = Arrays.copyOfRange(key, 1, key.length);
            KeyFactory kf = KeyFactory.getInstance("EC");
            int halfLength = rawBytes.length / 2;
            byte[] x = Arrays.copyOfRange(rawBytes, 0, halfLength);
            byte[] y = Arrays.copyOfRange(rawBytes, halfLength, rawBytes.length);
            ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            return (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(w, ecParameterSpecForCurve(curveName)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException e) {
            throw new RuntimeException(e);
        }
    }
    private static ECParameterSpec ecParameterSpecForCurve(String curveName) throws NoSuchAlgorithmException, InvalidParameterSpecException{
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curveName));
        return params.getParameterSpec(ECParameterSpec.class);
    }

    public static byte[] ecPublicKeyToUncompressedFormat(ECPublicKey ecPublicKey) {

        int keyLengthBytes = ecPublicKey.getParams().getOrder().bitLength() / 8;

        ECPoint point = ecPublicKey.getW();
        byte[] x = point.getAffineX().toByteArray();
        byte[] y = point.getAffineY().toByteArray();
        // remove leading zero in x and y if any
        if (x.length > keyLengthBytes && x[0] == 0x00) {
            x = Arrays.copyOfRange(x, 1, x.length);
        } else if (x.length < keyLengthBytes) {
            x = concat(new byte[keyLengthBytes - x.length], x);
        }
        if (y.length > keyLengthBytes && y[0] == 0x00) {
            y = Arrays.copyOfRange(y, 1, y.length);
        } else if (y.length < keyLengthBytes) {
            y = concat(new byte[keyLengthBytes - y.length], y);
        }

        // concat 0x04, x, and y
        return concat(new byte[] { 0x04 }, x, y);
    }

    private static byte[] concat(byte[]... elements) {
        int totalSize = Arrays.stream(elements).mapToInt(ar -> ar.length).sum();
        var result = new byte[totalSize];
        int i = 0;
        for (var element : elements) {
            System.arraycopy(element, 0, result, i, element.length);
            i += element.length;
        }
        return result;
    }


    @Test
    public void testUncompressed() throws Exception {
        var keyFactory = KeyFactory.getInstance("EC");
        var publicKey = (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(
                new BigInteger("73426278787780075375570657366715730875070048000196590484887790130887654534"),
                new BigInteger("74158927981933529681964219189946122388609927290306970061667498146082790857833")
        ), ecParameterSpecForCurve("secp256r1")));

        var encoded = ecPublicKeyToUncompressedFormat(publicKey);
        Assertions.assertThat(encoded).hasSize(65);
    }

    @Test
    public void findBadKey() throws Exception {
        var kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        while (true) {
            var keyPair = kpg.generateKeyPair();
            var publicKey = keyPair.getPublic();
            var encoded = ecPublicKeyToUncompressedFormat((ECPublicKey) publicKey);
            if (encoded.length != 65) {
                System.out.println("Found a bad key: " + Base64.getEncoder().encodeToString(encoded));
                System.out.println((ECPublicKey) publicKey);
                break;
            }
        }
    }

}