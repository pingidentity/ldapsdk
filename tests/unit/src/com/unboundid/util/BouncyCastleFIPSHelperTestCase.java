/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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



import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the Bouncy Castle FIPS helper
 * class.  Note that the LDAP SDK unit tests are not intended to be used when
 * the LDAP SDK has access to the Bouncy Castle libraries, and these tests are
 * written with that assumption.
 */
public final class BouncyCastleFIPSHelperTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the {@code getBouncyCastleFIPSProvider} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NoSuchProviderException.class })
  public void testGetBouncyCastleFIPSProvider()
         throws Exception
  {
    BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider();
  }



  /**
   * Provides test coverage for the {@code getBouncyCastleJSSEProvider} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NoSuchProviderException.class })
  public void testGetBouncyCastleJSSEProvider()
         throws Exception
  {
    BouncyCastleFIPSHelper.getBouncyCastleJSSEProvider();
  }



  /**
   * Provides test coverage for the methods used to control logging.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogging()
  {
    BouncyCastleFIPSHelper.disableLogging();

    Logger logger = BouncyCastleFIPSHelper.enableLogging(Level.WARNING);
    assertNotNull(logger);
    assertEquals(logger.getLevel(), Level.WARNING);
    assertFalse(logger.getUseParentHandlers());

    logger = BouncyCastleFIPSHelper.enableLogging(null);
    assertNotNull(logger);
    assertEquals(logger.getLevel(), Level.INFO);
    assertFalse(logger.getUseParentHandlers());

    BouncyCastleFIPSHelper.disableLogging();
    assertEquals(logger.getLevel(), Level.OFF);
  }
}
