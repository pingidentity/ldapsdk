/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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
 * {@link KeyStoreKeyManagerProperties} class.
 */
public final class KeyStoreKeyManagerPropertiesTestCase
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
    final File keyStoreFile = createTempFile();

    final KeyStoreKeyManagerProperties properties =
         new KeyStoreKeyManagerProperties(keyStoreFile);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the key store file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testKeyStorePath()
         throws Exception
  {
    final File originalKeyStoreFile = createTempFile();

    final KeyStoreKeyManagerProperties properties =
         new KeyStoreKeyManagerProperties(originalKeyStoreFile);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(),
         originalKeyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    final File replacementKeyStoreFile1 = createTempFile();
    properties.setKeyStoreFile(replacementKeyStoreFile1);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(),
         replacementKeyStoreFile1.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    final File replacementKeyStoreFile2 = createTempFile();
    properties.setKeyStorePath(replacementKeyStoreFile2.getAbsolutePath());

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(),
         replacementKeyStoreFile2.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the key store PIN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testKeyStorePIN()
         throws Exception
  {
    final File keyStoreFile = createTempFile();

    final KeyStoreKeyManagerProperties properties =
         new KeyStoreKeyManagerProperties(keyStoreFile);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setKeyStorePIN("pin1");

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNotNull(properties.getKeyStorePIN());
    assertTrue(Arrays.equals(properties.getKeyStorePIN(),
         "pin1".toCharArray()));

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setKeyStorePIN((String) null);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setKeyStorePIN("pin2".toCharArray());

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNotNull(properties.getKeyStorePIN());
    assertTrue(Arrays.equals(properties.getKeyStorePIN(),
         "pin2".toCharArray()));

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setKeyStorePIN((char[]) null);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the key store format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testKeyStoreFormat()
         throws Exception
  {
    final File keyStoreFile = createTempFile();

    final KeyStoreKeyManagerProperties properties =
         new KeyStoreKeyManagerProperties(keyStoreFile);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setKeyStoreFormat("JKS");

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNotNull(properties.getKeyStoreFormat());
    assertEquals(properties.getKeyStoreFormat(), "JKS");

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setKeyStoreFormat(null);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the certificate alias.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateAlias()
         throws Exception
  {
    final File keyStoreFile = createTempFile();

    final KeyStoreKeyManagerProperties properties =
         new KeyStoreKeyManagerProperties(keyStoreFile);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setCertificateAlias("server-cert");

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNotNull(properties.getCertificateAlias());
    assertEquals(properties.getCertificateAlias(), "server-cert");

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setCertificateAlias(null);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to validating the key store.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidateKeyStore()
         throws Exception
  {
    final File keyStoreFile = createTempFile();

    final KeyStoreKeyManagerProperties properties =
         new KeyStoreKeyManagerProperties(keyStoreFile);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setValidateKeyStore(true);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertTrue(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setValidateKeyStore(false);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

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
    final File keyStoreFile = createTempFile();

    final KeyStoreKeyManagerProperties properties =
         new KeyStoreKeyManagerProperties(keyStoreFile);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    final Provider[] providers = Security.getProviders();
    if ((providers == null) || (providers.length == 0))
    {
      return;
    }
    properties.setProvider(providers[0]);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNotNull(properties.getProvider());
    assertEquals(properties.getProvider(), providers[0]);

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setProvider(null);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the allowing non-FIPS-compliant key stores in
   * FIPS-compliant mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowNonFIPSInFIPSMode()
         throws Exception
  {
    final File keyStoreFile = createTempFile();

    final KeyStoreKeyManagerProperties properties =
         new KeyStoreKeyManagerProperties(keyStoreFile);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setAllowNonFIPSInFIPSMode(true);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertTrue(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());


    properties.setAllowNonFIPSInFIPSMode(false);

    assertNotNull(properties.getKeyStorePath());
    assertEquals(properties.getKeyStorePath(), keyStoreFile.getAbsolutePath());

    assertNull(properties.getKeyStorePIN());

    assertNull(properties.getKeyStoreFormat());

    assertNull(properties.getCertificateAlias());

    assertFalse(properties.validateKeyStore());

    assertNull(properties.getProvider());

    assertFalse(properties.allowNonFIPSInFIPSMode());

    assertNotNull(properties.toString());
  }
}
