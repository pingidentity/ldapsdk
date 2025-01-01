/*
 * Copyright 2024-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024-2025 Ping Identity Corporation
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
 * Copyright (C) 2024-2025 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the
 * {@link TrustStoreTrustManagerProperties} class.
 */
public final class TrustStoreTrustManagerPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that properties not set in the constructor have an
   * expected set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    final File trustStoreFile = createTempFile();

    final TrustStoreTrustManagerProperties properties =
         new TrustStoreTrustManagerProperties(trustStoreFile);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the trust store file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrustStorePath()
         throws Exception
  {
    final File originalTrustStoreFile = createTempFile();

    final TrustStoreTrustManagerProperties properties =
         new TrustStoreTrustManagerProperties(originalTrustStoreFile);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         originalTrustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    final File replacementTrustStoreFile1 = createTempFile();
    properties.setTrustStoreFile(replacementTrustStoreFile1);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         replacementTrustStoreFile1.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    final File replacementTrustStoreFile2 = createTempFile();
    properties.setTrustStorePath(replacementTrustStoreFile2.getAbsolutePath());

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         replacementTrustStoreFile2.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the trust store PIN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrustStorePIN()
         throws Exception
  {
    final File trustStoreFile = createTempFile();

    final TrustStoreTrustManagerProperties properties =
         new TrustStoreTrustManagerProperties(trustStoreFile);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setTrustStorePIN("pin1");

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNotNull(properties.getTrustStorePIN());
    assertTrue(Arrays.equals(properties.getTrustStorePIN(),
         "pin1".toCharArray()));

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setTrustStorePIN((String) null);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setTrustStorePIN("pin2".toCharArray());

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNotNull(properties.getTrustStorePIN());
    assertTrue(Arrays.equals(properties.getTrustStorePIN(),
         "pin2".toCharArray()));

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setTrustStorePIN((char[]) null);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the trust store format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrustStoreFormat()
         throws Exception
  {
    final File trustStoreFile = createTempFile();

    final TrustStoreTrustManagerProperties properties =
         new TrustStoreTrustManagerProperties(trustStoreFile);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setTrustStoreFormat("JKS");

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNotNull(properties.getTrustStoreFormat());
    assertEquals(properties.getTrustStoreFormat(), "JKS");

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setTrustStoreFormat(null);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to examining validity dates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExamineValidityDates()
         throws Exception
  {
    final File trustStoreFile = createTempFile();

    final TrustStoreTrustManagerProperties properties =
         new TrustStoreTrustManagerProperties(trustStoreFile);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setExamineValidityDates(false);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertFalse(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setExamineValidityDates(true);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the security provider.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProvider()
         throws Exception
  {
    final File trustStoreFile = createTempFile();

    final TrustStoreTrustManagerProperties properties =
         new TrustStoreTrustManagerProperties(trustStoreFile);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    final Provider[] providers = Security.getProviders();
    if ((providers == null) || (providers.length == 0))
    {
      return;
    }
    properties.setProvider(providers[0]);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNotNull(properties.getProvider());
    assertEquals(properties.getProvider(), providers[0]);

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setProvider(null);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the allowing non-FIPS-compliant trust stores in
   * FIPS-compliant mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowNonFIPSInFIPSMode()
         throws Exception
  {
    final File trustStoreFile = createTempFile();

    final TrustStoreTrustManagerProperties properties =
         new TrustStoreTrustManagerProperties(trustStoreFile);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setAllowNonFIPSInFIPSMode(true);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertTrue(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setAllowNonFIPSInFIPSMode(false);

    assertNotNull(properties.getTrustStorePath());
    assertEquals(properties.getTrustStorePath(),
         trustStoreFile.getAbsolutePath());

    assertNull(properties.getTrustStorePIN());

    assertNull(properties.getTrustStoreFormat());

    assertTrue(properties.examineValidityDates());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }
}
