/*
 * Copyright 2009-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 UnboundID Corp.
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



import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the LDAPSDKUsageException class.
 */
public class LDAPSDKUsageExceptionTestCase
       extends UtilTestCase
{
  /**
   * Provides coverage for the first constructor, which takes only a string.
   */
  @Test()
  public void testConstructor1()
  {
    LDAPSDKUsageException e = new LDAPSDKUsageException("foo");

    assertTrue(e instanceof LDAPSDKRuntimeException);
    assertTrue(e instanceof RuntimeException);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "foo");

    assertNull(e.getCause());

    assertNotNull(e.toString());

    assertNotNull(e.getExceptionMessage());
    assertEquals(e.getExceptionMessage(), "foo");

    assertNotNull(StaticUtils.getStackTrace(e));
  }



  /**
   * Provides coverage for the second constructor, which takes a string and a
   * Throwable.
   */
  @Test()
  public void testConstructor2()
  {
    Exception cause = new Exception();
    LDAPSDKUsageException e = new LDAPSDKUsageException("foo", cause);

    assertTrue(e instanceof LDAPSDKRuntimeException);
    assertTrue(e instanceof RuntimeException);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "foo");

    assertNotNull(e.getCause());
    assertEquals(e.getCause(), cause);

    assertNotNull(e.toString());

    assertNotNull(e.getExceptionMessage());
    assertEquals(e.getExceptionMessage(), "foo");

    assertNotNull(StaticUtils.getStackTrace(e));
  }
}
