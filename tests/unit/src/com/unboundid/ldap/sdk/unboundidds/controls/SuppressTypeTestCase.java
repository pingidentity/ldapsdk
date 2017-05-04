/*
 * Copyright 2012-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2017 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code SuppressType} enum.
 */
public final class SuppressTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the methods provided in the enum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnumMethods()
         throws Exception
  {
    for (final SuppressType t : SuppressType.values())
    {
      assertNotNull(t.name());
      assertEquals(SuppressType.valueOf(t.name()), t);
      assertEquals(SuppressType.valueOf(t.intValue()), t);
    }

    assertNull(SuppressType.valueOf(12345));

    try
    {
      SuppressType.valueOf("undefined");
      fail("Expected an exception from valueOf with an undefined string");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }
}
