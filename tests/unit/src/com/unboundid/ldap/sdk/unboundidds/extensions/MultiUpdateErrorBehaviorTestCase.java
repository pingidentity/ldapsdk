/*
 * Copyright 2012-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2017 UnboundID Corp.
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
 * This class provides a set of test cases for the multi-update error behavior
 * class.
 */
public final class MultiUpdateErrorBehaviorTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for each of the error behaviors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testErrorBehaviors()
         throws Exception
  {
    for (final MultiUpdateErrorBehavior b : MultiUpdateErrorBehavior.values())
    {
      assertNotNull(b);

      assertEquals(MultiUpdateErrorBehavior.valueOf(b.intValue()), b);

      assertEquals(MultiUpdateErrorBehavior.valueOf(b.name()), b);
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
    assertNull(MultiUpdateErrorBehavior.valueOf(12345));
  }
}
