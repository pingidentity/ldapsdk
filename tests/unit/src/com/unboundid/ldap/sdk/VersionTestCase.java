/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.testng.annotations.Test;



/**
 * This class provides test coverage for the Version class.
 */
public class VersionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provide test coverage for the {@code main} method.
   */
  @Test()
  public void testMain()
  {
    PrintStream originalOut = System.out;
    ByteArrayOutputStream byteArrayStream = new ByteArrayOutputStream();
    PrintStream newOut = new PrintStream(byteArrayStream);

    try
    {
      System.setOut(newOut);
      Version.main();

      byte[] outputBytes = byteArrayStream.toByteArray();
      assertNotNull(outputBytes);
      assertTrue(outputBytes.length > 0);
    }
    finally
    {
      System.setOut(originalOut);
      newOut.close();
    }
  }



  /**
   * Tests the methods that can be used to obtain version information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVersionMethods()
         throws Exception
  {
    assertEquals(Version.getProductName(), Version.PRODUCT_NAME);

    assertEquals(Version.getShortName(), Version.SHORT_NAME);

    assertEquals(Version.getMajorVersion(), Version.MAJOR_VERSION);

    assertEquals(Version.getMinorVersion(), Version.MINOR_VERSION);

    assertEquals(Version.getPointVersion(), Version.POINT_VERSION);

    assertEquals(Version.getVersionQualifier(), Version.VERSION_QUALIFIER);

    assertEquals(Version.getBuildTimestamp(), Version.BUILD_TIMESTAMP);

    assertEquals(Version.getRepositoryType(), Version.REPOSITORY_TYPE);

    assertEquals(Version.getRepositoryURL(), Version.REPOSITORY_URL);

    assertEquals(Version.getRepositoryPath(), Version.REPOSITORY_PATH);

    assertEquals(Version.getRevisionID(), Version.REVISION_ID);

    assertEquals(Version.getFullVersionString(), Version.FULL_VERSION_STRING);

    assertEquals(Version.getShortVersionString(), Version.SHORT_VERSION_STRING);

    assertEquals(Version.getNumericVersionString(),
         Version.NUMERIC_VERSION_STRING);

    assertNotNull(Version.getVersionLines());
    assertFalse(Version.getVersionLines().isEmpty());
  }
}
