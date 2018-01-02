/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code LogException} class.
 */
public class LogExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which takes a log message and an explanation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    LogException le = new LogException("log message", "explanation");

    assertNotNull(le.getLogMessage());
    assertEquals(le.getLogMessage(), "log message");

    assertNotNull(le.getMessage());
    assertEquals(le.getMessage(), "explanation");

    assertNull(le.getCause());

    assertNotNull(le.toString());

    assertNotNull(le.getExceptionMessage());
  }



  /**
   * Tests the second constructor, which takes a log message and an explanation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    LogException le = new LogException("log message", "explanation",
                                       new Exception());

    assertNotNull(le.getLogMessage());
    assertEquals(le.getLogMessage(), "log message");

    assertNotNull(le.getMessage());
    assertEquals(le.getMessage(), "explanation");

    assertNotNull(le.getCause());

    assertNotNull(le.toString());

    assertNotNull(le.getExceptionMessage());
  }
}
