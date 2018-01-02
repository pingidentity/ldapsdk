/*
 * Copyright 2013-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2018 Ping Identity Corporation
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
 * This class provides a set of test cases for the get configuration type enum.
 */
public final class GetConfigurationTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the get configuration type enum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetConfigurationType()
         throws Exception
  {
    for (final GetConfigurationType t : GetConfigurationType.values())
    {
      assertEquals(GetConfigurationType.forBERType(t.getBERType()), t);
      assertEquals(GetConfigurationType.forIntValue(t.getIntValue()), t);
      assertEquals(GetConfigurationType.valueOf(t.name()), t);
    }

    assertNull(GetConfigurationType.forBERType((byte) 0x00));
    assertNull(GetConfigurationType.forIntValue(12345));

    try
    {
      GetConfigurationType.valueOf("invalid");
      fail("Expected an exception on valueOf with an invalid name");
    }
    catch (final IllegalArgumentException iae)
    {
      // This was expected.
    }
  }
}
