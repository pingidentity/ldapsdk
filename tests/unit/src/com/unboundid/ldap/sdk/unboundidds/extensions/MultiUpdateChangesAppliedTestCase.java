/*
 * Copyright 2012-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the multi-update changes applied
 * class.
 */
public final class MultiUpdateChangesAppliedTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for each of the changes applied values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesAppliedValues()
         throws Exception
  {
    for (final MultiUpdateChangesApplied v : MultiUpdateChangesApplied.values())
    {
      assertNotNull(v);

      assertEquals(MultiUpdateChangesApplied.valueOf(v.intValue()), v);

      assertEquals(MultiUpdateChangesApplied.valueOf(v.name()), v);
    }
  }



  /**
   * Tests the behavior of the valueOf method with an undefined value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOfUndefined()
         throws Exception
  {
    assertNull(MultiUpdateChangesApplied.valueOf(12345));
  }
}
