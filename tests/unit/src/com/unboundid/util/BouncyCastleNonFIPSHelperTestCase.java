/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.File;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the Bouncy Castle non-FIPS
 * helper.
 */
public final class BouncyCastleNonFIPSHelperTestCase
       extends LDAPSDKTestCase
{
  /**
   * The name of the system property used to determine the Ping Identty server
   * root.
   */
  private static final String SERVER_ROOT_PROPERTY =
       "com.unboundid.directory.server.ServerRoot";



  // A file that representsthe path to an empty directory.
  private File testEmptyServerRoot;

  // A file that represents the path to a simulated server root with an empty
  // resource/be/non-fips directory.
  private File testServerRootWithEmptyNonFIPSDir;

  // The initial value for the system property used to
  private String initialServerRootPropertyValue;



  /**
   * Captures the initial value for the property used to specify the Ping
   * Identity server root, and then clears it so that it will be unset by
   * default for all test methods in this class.  Also, creates a simulated
   * server root with an empty resource/bc/non-fips directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    initialServerRootPropertyValue =
         StaticUtils.getSystemProperty(SERVER_ROOT_PROPERTY);
    StaticUtils.clearSystemProperty(SERVER_ROOT_PROPERTY);

    assertNull(InternalSDKHelper.getPingIdentityServerRoot());

    testEmptyServerRoot = createTempDir();

    testServerRootWithEmptyNonFIPSDir = createTempDir();
    final File nonFIPSDir = StaticUtils.constructPath(
         testServerRootWithEmptyNonFIPSDir, "resource", "bc", "non-fips");
    assertTrue(nonFIPSDir.mkdirs());
  }



  /**
   * Restores the initial value for the property used to specify the Ping
   * Identity server root.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if (initialServerRootPropertyValue == null)
    {
      StaticUtils.clearSystemProperty(SERVER_ROOT_PROPERTY);
    }
    else
    {
      StaticUtils.setSystemProperty(SERVER_ROOT_PROPERTY,
           initialServerRootPropertyValue);
    }

    delete(testEmptyServerRoot);
    delete(testServerRootWithEmptyNonFIPSDir);
  }



  /**
   * Tests the behavior when the server root system property is not set and the
   * method should fall back to using the JVM's default class loader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertyNotSetWithFallBack()
         throws Exception
  {
    assertNull(InternalSDKHelper.getPingIdentityServerRoot());

    final ClassLoader classLoader =
         BouncyCastleNonFIPSHelper.getNonFIPSBouncyCastleClassLoader(true);
    assertNotNull(classLoader);
  }



  /**
   * Tests the behavior when the server root system property is not set and the
   * method should not fall back to using the JVM's default class loader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ReflectiveOperationException.class })
  public void testPropertyNotSetWithoutFallBack()
         throws Exception
  {
    assertNull(InternalSDKHelper.getPingIdentityServerRoot());

    BouncyCastleNonFIPSHelper.getNonFIPSBouncyCastleClassLoader(false);
  }



  /**
   * Tests the behavior when the server root system property is set and the
   * resource/bc/non-fips directory exists but is empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyServerRootWithFallBack()
         throws Exception
  {
    StaticUtils.setSystemProperty(SERVER_ROOT_PROPERTY,
         testEmptyServerRoot.getAbsolutePath());
    try
    {
      assertNotNull(InternalSDKHelper.getPingIdentityServerRoot());

      final ClassLoader classLoader =
           BouncyCastleNonFIPSHelper.getNonFIPSBouncyCastleClassLoader(true);
      assertNotNull(classLoader);
    }
    finally
    {
      StaticUtils.clearSystemProperty(SERVER_ROOT_PROPERTY);
    }
  }



  /**
   * Tests the behavior when the server root system property is not set and the
   * method should not fall back to using the JVM's default class loader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ReflectiveOperationException.class })
  public void testEmptyServerRootWithoutFallBack()
         throws Exception
  {
    StaticUtils.setSystemProperty(SERVER_ROOT_PROPERTY,
         testEmptyServerRoot.getAbsolutePath());
    try
    {
      assertNotNull(InternalSDKHelper.getPingIdentityServerRoot());

      final ClassLoader classLoader =
           BouncyCastleNonFIPSHelper.getNonFIPSBouncyCastleClassLoader(false);
      assertNotNull(classLoader);
    }
    finally
    {
      StaticUtils.clearSystemProperty(SERVER_ROOT_PROPERTY);
    }
  }



  /**
   * Tests the behavior when the server root system property is set and the
   * resource/bc/non-fips directory exists but is empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyNonFIPSDirWithFallBack()
         throws Exception
  {
    StaticUtils.setSystemProperty(SERVER_ROOT_PROPERTY,
         testServerRootWithEmptyNonFIPSDir.getAbsolutePath());
    try
    {
      assertNotNull(InternalSDKHelper.getPingIdentityServerRoot());

      final ClassLoader classLoader =
           BouncyCastleNonFIPSHelper.getNonFIPSBouncyCastleClassLoader(true);
      assertNotNull(classLoader);
    }
    finally
    {
      StaticUtils.clearSystemProperty(SERVER_ROOT_PROPERTY);
    }
  }



  /**
   * Tests the behavior when the server root system property is not set and the
   * method should not fall back to using the JVM's default class loader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ReflectiveOperationException.class })
  public void testEmptyNonFIPSDirWithoutFallBack()
         throws Exception
  {
    StaticUtils.setSystemProperty(SERVER_ROOT_PROPERTY,
         testServerRootWithEmptyNonFIPSDir.getAbsolutePath());
    try
    {
      assertNotNull(InternalSDKHelper.getPingIdentityServerRoot());

      final ClassLoader classLoader =
           BouncyCastleNonFIPSHelper.getNonFIPSBouncyCastleClassLoader(false);
      assertNotNull(classLoader);
    }
    finally
    {
      StaticUtils.clearSystemProperty(SERVER_ROOT_PROPERTY);
    }
  }
}
