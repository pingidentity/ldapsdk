/*
 * Copyright 2007-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the DisconnectType class.
 */
public class DisconnectTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for all methods in the disconnect type class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefinedDisconnectTypes()
         throws Exception
  {
    for (DisconnectType t : DisconnectType.values())
    {
      assertNotNull(t.name());
      assertNotNull(t.getDescription());
      assertNotNull(t.toString());

      assertEquals(DisconnectType.forName(t.name().toLowerCase()), t);
      assertEquals(DisconnectType.forName(t.name()), t);
      assertEquals(DisconnectType.valueOf(t.name()), t);
    }
  }



  /**
   * Ensures that {@code forName} returns {@code null} for an undefined type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameUndefined()
         throws Exception
  {
    assertNull(DisconnectType.forName("undefined"));
  }



  /**
   * Tests the {@code isExpected} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsExpected()
         throws Exception
  {
    for (DisconnectType t : DisconnectType.values())
    {
      DisconnectType.isExpected(t);
    }
  }
}
