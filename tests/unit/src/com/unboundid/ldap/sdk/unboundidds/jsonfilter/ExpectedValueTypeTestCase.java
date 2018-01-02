/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.jsonfilter;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code ExpectedValueType}
 * class.
 */
public final class ExpectedValueTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the enum values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnumValues()
         throws Exception
  {
    for (final ExpectedValueType t : ExpectedValueType.values())
    {
      assertNotNull(t.toString());
      assertEquals(ExpectedValueType.forName(t.toString()), t);
      assertEquals(ExpectedValueType.valueOf(t.name()), t);
    }
  }



  /**
   * Tests the behavior of the {@code valueOf} method with an unrecognized
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IllegalArgumentException.class })
  public void testValueOfUnrecognized()
         throws Exception
  {
    ExpectedValueType.valueOf("unrecognized");
  }
}
