/*
 * Copyright 2008-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the FailedDependencyAction class.
 */
public class FailedDependencyActionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic coverage for FailedDependencyAction values.
   *
   * @param  a  The failed dependency action value to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "failedDependencyActions")
  public void testFailedDependencyAction(final FailedDependencyAction a)
         throws Exception
  {
    assertNotNull(a);

    assertEquals(FailedDependencyAction.valueOf(a.name()), a);

    assertEquals(FailedDependencyAction.forName(a.getName()), a);

    assertNotNull(a.getName());
    assertNotNull(a.toString());
  }



  /**
   * Retrieves the set of defined failed dependency actions.
   *
   * @return  The set of defined failed dependency actions.
   */
  @DataProvider(name = "failedDependencyActions")
  public Object[][] getFailedDependencyActions()
  {
    FailedDependencyAction[] values = FailedDependencyAction.values();
    Object[][] returnArray = new Object[values.length][1];
    for (int i=0; i < values.length; i++)
    {
      returnArray[i][0] = values[i];
    }

    return returnArray;
  }



  /**
   * Tests the {@code forName} method with an invalid value.
   */
  @Test()
  public void testForNameInvalid()
  {
    assertNull(FailedDependencyAction.forName("invalid"));
  }
}
