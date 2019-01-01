/*
 * Copyright 2009-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2019 Ping Identity Corporation
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
}
