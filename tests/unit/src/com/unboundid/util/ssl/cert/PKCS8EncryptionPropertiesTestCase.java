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



/**
 * This class provides a set of test cases for the PKCS #8 encryption properties
 * class.
 */
public final class PKCS8EncryptionPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the default values for all properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    final PKCS8EncryptionProperties properties =
         new PKCS8EncryptionProperties();

    assertEquals(properties.getKeyFactoryPRFAlgorithm(),
         PKCS5AlgorithmIdentifier.HMAC_SHA_256);

    assertEquals(properties.getKeyFactoryIterationCount(), 2048);

    assertEquals(properties.getKeyFactorySaltLengthBytes(), 8);

    assertEquals(properties.getCipherTransformationAlgorithm(),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior of the methods related to the key factory PRF algorithm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testKeyFactoryPRFAlgorithm()
         throws Exception
  {
    final PKCS8EncryptionProperties properties =
         new PKCS8EncryptionProperties();

    assertEquals(properties.getKeyFactoryPRFAlgorithm(),
         PKCS5AlgorithmIdentifier.HMAC_SHA_256);

    assertEquals(properties.getKeyFactoryIterationCount(), 2048);

    assertEquals(properties.getKeyFactorySaltLengthBytes(), 8);

    assertEquals(properties.getCipherTransformationAlgorithm(),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);

    assertNotNull(properties.toString());


    properties.setKeyFactoryPRFAlgorithm(
         PKCS5AlgorithmIdentifier.HMAC_SHA_512);

    assertEquals(properties.getKeyFactoryPRFAlgorithm(),
         PKCS5AlgorithmIdentifier.HMAC_SHA_512);

    assertEquals(properties.getKeyFactoryIterationCount(), 2048);

    assertEquals(properties.getKeyFactorySaltLengthBytes(), 8);

    assertEquals(properties.getCipherTransformationAlgorithm(),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);

    assertNotNull(properties.toString());


    try
    {
      properties.setKeyFactoryPRFAlgorithm(
           PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);
      fail("Expected an exception when trying to use a non-PRF algorithm.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the methods related to the key factory iteration
   * count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testKeyFactoryIterationCount()
         throws Exception
  {
    final PKCS8EncryptionProperties properties =
         new PKCS8EncryptionProperties();

    assertEquals(properties.getKeyFactoryPRFAlgorithm(),
         PKCS5AlgorithmIdentifier.HMAC_SHA_256);

    assertEquals(properties.getKeyFactoryIterationCount(), 2048);

    assertEquals(properties.getKeyFactorySaltLengthBytes(), 8);

    assertEquals(properties.getCipherTransformationAlgorithm(),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);

    assertNotNull(properties.toString());


    properties.setKeyFactoryIterationCount(4096);

    assertEquals(properties.getKeyFactoryPRFAlgorithm(),
         PKCS5AlgorithmIdentifier.HMAC_SHA_256);

    assertEquals(properties.getKeyFactoryIterationCount(), 4096);

    assertEquals(properties.getKeyFactorySaltLengthBytes(), 8);

    assertEquals(properties.getCipherTransformationAlgorithm(),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior of the methods related to the key factory salt length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testKeyFactorySaltLengthBytes()
         throws Exception
  {
    final PKCS8EncryptionProperties properties =
         new PKCS8EncryptionProperties();

    assertEquals(properties.getKeyFactoryPRFAlgorithm(),
         PKCS5AlgorithmIdentifier.HMAC_SHA_256);

    assertEquals(properties.getKeyFactoryIterationCount(), 2048);

    assertEquals(properties.getKeyFactorySaltLengthBytes(), 8);

    assertEquals(properties.getCipherTransformationAlgorithm(),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);

    assertNotNull(properties.toString());


    properties.setKeyFactorySaltLengthBytes(16);

    assertEquals(properties.getKeyFactoryPRFAlgorithm(),
         PKCS5AlgorithmIdentifier.HMAC_SHA_256);

    assertEquals(properties.getKeyFactoryIterationCount(), 2048);

    assertEquals(properties.getKeyFactorySaltLengthBytes(), 16);

    assertEquals(properties.getCipherTransformationAlgorithm(),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior of the methods related to the cipher transformation
   * algorithm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCipherTransformationAlgorithm()
         throws Exception
  {
    final PKCS8EncryptionProperties properties =
         new PKCS8EncryptionProperties();

    assertEquals(properties.getKeyFactoryPRFAlgorithm(),
         PKCS5AlgorithmIdentifier.HMAC_SHA_256);

    assertEquals(properties.getKeyFactoryIterationCount(), 2048);

    assertEquals(properties.getKeyFactorySaltLengthBytes(), 8);

    assertEquals(properties.getCipherTransformationAlgorithm(),
         PKCS5AlgorithmIdentifier.AES_128_CBC_PAD);

    assertNotNull(properties.toString());


    properties.setCipherTransformationAlgorithm(
         PKCS5AlgorithmIdentifier.AES_256_CBC_PAD);

    assertEquals(properties.getKeyFactoryPRFAlgorithm(),
         PKCS5AlgorithmIdentifier.HMAC_SHA_256);

    assertEquals(properties.getKeyFactoryIterationCount(), 2048);

    assertEquals(properties.getKeyFactorySaltLengthBytes(), 8);

    assertEquals(properties.getCipherTransformationAlgorithm(),
         PKCS5AlgorithmIdentifier.AES_256_CBC_PAD);

    assertNotNull(properties.toString());


    try
    {
      properties.setCipherTransformationAlgorithm(
           PKCS5AlgorithmIdentifier.PBES2);
      fail("Expected an exception when trying to use a non-cipher " +
           "transformation.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }
}
