/*
 * Copyright 2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017 Ping Identity Corporation
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
 * This class provides a set of test cases for the uniqueness validation level
 * enum.
 */
public final class UniquenessValidationLevelTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the enum values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnumMethods()
         throws Exception
  {
    for (final UniquenessValidationLevel l : UniquenessValidationLevel.values())
    {
      assertNotNull(l.name());
      assertEquals(UniquenessValidationLevel.valueOf(l.name()), l);
      assertEquals(UniquenessValidationLevel.valueOf(l.intValue()), l);
    }

    assertNull(UniquenessValidationLevel.valueOf(12345));

    try
    {
      UniquenessValidationLevel.valueOf("undefined");
      fail("Expected an exception from valueOf with an undefined string");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }
}
