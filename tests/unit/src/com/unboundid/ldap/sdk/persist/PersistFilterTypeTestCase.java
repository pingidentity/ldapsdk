/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.persist;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the PersistFilterType class.
 */
public final class PersistFilterTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the persist filter type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPersistFilterType()
         throws Exception
  {
    for (final PersistFilterType t : PersistFilterType.values())
    {
      t.ordinal();

      assertNotNull(t.name());
      assertEquals(PersistFilterType.valueOf(t.name()), t);

      assertNotNull(t.toString());
    }

    assertEquals(PersistFilterType.valueOf("PRESENCE"),
         PersistFilterType.PRESENCE);
    assertEquals(PersistFilterType.valueOf("EQUALITY"),
         PersistFilterType.EQUALITY);
    assertEquals(PersistFilterType.valueOf("STARTS_WITH"),
         PersistFilterType.STARTS_WITH);
    assertEquals(PersistFilterType.valueOf("ENDS_WITH"),
         PersistFilterType.ENDS_WITH);
    assertEquals(PersistFilterType.valueOf("CONTAINS"),
         PersistFilterType.CONTAINS);
    assertEquals(PersistFilterType.valueOf("GREATER_OR_EQUAL"),
         PersistFilterType.GREATER_OR_EQUAL);
    assertEquals(PersistFilterType.valueOf("LESS_OR_EQUAL"),
         PersistFilterType.LESS_OR_EQUAL);
    assertEquals(PersistFilterType.valueOf("APPROXIMATELY_EQUAL_TO"),
         PersistFilterType.APPROXIMATELY_EQUAL_TO);
  }
}
