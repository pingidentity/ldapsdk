/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2022-2024 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.util.ssl.cert;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the PKCS #5 algorithm identifier
 * enum.
 */
public final class PKCS5AlgorithmIdentifierTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the enum methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnumMethods()
         throws Exception
  {
    for (final PKCS5AlgorithmIdentifier v : PKCS5AlgorithmIdentifier.values())
    {
      assertEquals(PKCS5AlgorithmIdentifier.valueOf(v.name()), v);

      assertNotNull(v.getOID());

      assertNotNull(v.getName());

      assertEquals(PKCS5AlgorithmIdentifier.getNameOrOID(v.getOID()),
           v.getName());

      assertNotNull(v.getDescription());

      assertNotNull(v.toString());

      assertEquals(PKCS5AlgorithmIdentifier.forOID(v.getOID()), v);

      assertEquals(PKCS5AlgorithmIdentifier.forName(v.getName()), v);
      assertEquals(PKCS5AlgorithmIdentifier.forName(v.name()), v);
    }
  }



  /**
   * Provides test coverage for the forOID method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForOID()
         throws Exception
  {
    assertEquals(
         PKCS5AlgorithmIdentifier.forOID(
              PKCS5AlgorithmIdentifier.PBES2.getOID()),
         PKCS5AlgorithmIdentifier.PBES2);

    assertNull(PKCS5AlgorithmIdentifier.forOID(new OID(1, 2, 3, 4)));
  }



  /**
   * Provides test coverage for the forName method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForName()
         throws Exception
  {
    assertEquals(
         PKCS5AlgorithmIdentifier.forName("AES-128-CBC-PAD"),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);
    assertEquals(
         PKCS5AlgorithmIdentifier.forName("aes-128-cbc-pad"),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);
    assertEquals(
         PKCS5AlgorithmIdentifier.forName("aes128cbcpad"),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);
    assertEquals(
         PKCS5AlgorithmIdentifier.forName("aes"),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);
    assertEquals(
         PKCS5AlgorithmIdentifier.forName("aes128"),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);
    assertEquals(
         PKCS5AlgorithmIdentifier.forName("AES-128"),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);
    assertEquals(
         PKCS5AlgorithmIdentifier.forName("AES 128"),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);
    assertEquals(
         PKCS5AlgorithmIdentifier.forName("AES/CBC/PKCS5Padding"),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);

    assertNull(PKCS5AlgorithmIdentifier.forName("NOT-A-RECOGNIZED-NAME"));
  }



  /**
   * Provides test coverage for the getNameOrOID method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNameOrOID()
         throws Exception
  {
    assertEquals(
         PKCS5AlgorithmIdentifier.getNameOrOID(
              PKCS5AlgorithmIdentifier.AES_256_CBC_PAD.getOID()),
         PKCS5AlgorithmIdentifier.AES_256_CBC_PAD.getName());

    assertEquals(
         PKCS5AlgorithmIdentifier.getNameOrOID(new OID(1, 2, 3, 4)),
         "1.2.3.4");
  }



  /**
   * Provides test coverage for the methods specific to pseudorandom functions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPseudorandomFunctions()
         throws Exception
  {
    assertEquals(PKCS5AlgorithmIdentifier.getPseudorandomFunctions(),
         StaticUtils.setOf(
              PKCS5AlgorithmIdentifier.HMAC_SHA_1,
              PKCS5AlgorithmIdentifier.HMAC_SHA_224,
              PKCS5AlgorithmIdentifier.HMAC_SHA_256,
              PKCS5AlgorithmIdentifier.HMAC_SHA_384,
              PKCS5AlgorithmIdentifier.HMAC_SHA_512));

    assertEquals(
         PKCS5AlgorithmIdentifier.
              getPBKDF2SecretKeyFactoryAlgorithmForPseudorandomFunction(
                   PKCS5AlgorithmIdentifier.HMAC_SHA_1),
         "PBKDF2WithHmacSHA1");
    assertEquals(
         PKCS5AlgorithmIdentifier.
              getPBKDF2SecretKeyFactoryAlgorithmForPseudorandomFunction(
                   PKCS5AlgorithmIdentifier.HMAC_SHA_224),
         "PBKDF2WithHmacSHA224");
    assertEquals(
         PKCS5AlgorithmIdentifier.
              getPBKDF2SecretKeyFactoryAlgorithmForPseudorandomFunction(
                   PKCS5AlgorithmIdentifier.HMAC_SHA_256),
         "PBKDF2WithHmacSHA256");
    assertEquals(
         PKCS5AlgorithmIdentifier.
              getPBKDF2SecretKeyFactoryAlgorithmForPseudorandomFunction(
                   PKCS5AlgorithmIdentifier.HMAC_SHA_384),
         "PBKDF2WithHmacSHA384");
    assertEquals(
         PKCS5AlgorithmIdentifier.
              getPBKDF2SecretKeyFactoryAlgorithmForPseudorandomFunction(
                   PKCS5AlgorithmIdentifier.HMAC_SHA_512),
         "PBKDF2WithHmacSHA512");
    assertNull(PKCS5AlgorithmIdentifier.
         getPBKDF2SecretKeyFactoryAlgorithmForPseudorandomFunction(
              PKCS5AlgorithmIdentifier.PBKDF2));
  }



  /**
   * Provides test coverage for methods specific to cipher transformations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCipherTransformations()
         throws Exception
  {
    assertEquals(PKCS5AlgorithmIdentifier.getCipherTransformations(),
         StaticUtils.setOf(
              PKCS5AlgorithmIdentifier.DES_EDE3_CBC_PAD,
              PKCS5AlgorithmIdentifier.AES_128_CBC_PAD,
              PKCS5AlgorithmIdentifier.AES_192_CBC_PAD,
              PKCS5AlgorithmIdentifier.AES_256_CBC_PAD));

    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherAlgorithmName(
              PKCS5AlgorithmIdentifier.DES_EDE3_CBC_PAD),
         "DESede");
    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherAlgorithmName(
              PKCS5AlgorithmIdentifier.AES_128_CBC_PAD),
         "AES");
    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherAlgorithmName(
              PKCS5AlgorithmIdentifier.AES_192_CBC_PAD),
         "AES");
    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherAlgorithmName(
              PKCS5AlgorithmIdentifier.AES_256_CBC_PAD),
         "AES");
    assertNull(
         PKCS5AlgorithmIdentifier.getCipherAlgorithmName(
              PKCS5AlgorithmIdentifier.HMAC_SHA_1));

    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherTransformationName(
              PKCS5AlgorithmIdentifier.DES_EDE3_CBC_PAD),
         "DESede/CBC/PKCS5Padding");
    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherTransformationName(
              PKCS5AlgorithmIdentifier.AES_128_CBC_PAD),
         "AES/CBC/PKCS5Padding");
    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherTransformationName(
              PKCS5AlgorithmIdentifier.AES_192_CBC_PAD),
         "AES/CBC/PKCS5Padding");
    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherTransformationName(
              PKCS5AlgorithmIdentifier.AES_256_CBC_PAD),
         "AES/CBC/PKCS5Padding");
    assertNull(
         PKCS5AlgorithmIdentifier.getCipherTransformationName(
              PKCS5AlgorithmIdentifier.HMAC_SHA_1));

    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherKeySizeBits(
              PKCS5AlgorithmIdentifier.DES_EDE3_CBC_PAD).intValue(),
         192);
    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherKeySizeBits(
              PKCS5AlgorithmIdentifier.AES_128_CBC_PAD).intValue(),
         128);
    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherKeySizeBits(
              PKCS5AlgorithmIdentifier.AES_192_CBC_PAD).intValue(),
         192);
    assertEquals(
         PKCS5AlgorithmIdentifier.getCipherKeySizeBits(
              PKCS5AlgorithmIdentifier.AES_256_CBC_PAD).intValue(),
         256);
    assertNull(
         PKCS5AlgorithmIdentifier.getCipherKeySizeBits(
              PKCS5AlgorithmIdentifier.HMAC_SHA_1));
  }
}
