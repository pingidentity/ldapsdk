/*
 * Copyright 2015-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2017 Ping Identity Corporation
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
 * This class provides a set of test cases for the set notification destination
 * change type enum.
 */
public final class SetNotificationDestinationChangeTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the change types enum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangeTypes()
         throws Exception
  {
    assertEquals(SetNotificationDestinationChangeType.REPLACE.intValue(), 0);
    assertEquals(SetNotificationDestinationChangeType.valueOf(0),
         SetNotificationDestinationChangeType.REPLACE);

    assertEquals(SetNotificationDestinationChangeType.ADD.intValue(), 1);
    assertEquals(SetNotificationDestinationChangeType.valueOf(1),
         SetNotificationDestinationChangeType.ADD);

    assertEquals(SetNotificationDestinationChangeType.DELETE.intValue(), 2);
    assertEquals(SetNotificationDestinationChangeType.valueOf(2),
         SetNotificationDestinationChangeType.DELETE);

    for (final SetNotificationDestinationChangeType t :
         SetNotificationDestinationChangeType.values())
    {
      assertEquals(SetNotificationDestinationChangeType.valueOf(t.intValue()),
           t);
      assertEquals(SetNotificationDestinationChangeType.valueOf(t.name()),
           t);
    }

    assertNull(SetNotificationDestinationChangeType.valueOf(3));

    try
    {
      SetNotificationDestinationChangeType.valueOf("undefined");
      fail("Expected an exception from an undefined string valueOf");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }
}
