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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the assured replication server
 * result code enum.
 */
public final class AssuredReplicationServerResultCodeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides general test coverage for the enum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneral()
         throws Exception
  {
    // Test with valid values.
    for (final AssuredReplicationServerResultCode rc :
         AssuredReplicationServerResultCode.values())
    {
      assertNotNull(rc.name());
      assertNotNull(rc.intValue());
      assertEquals(AssuredReplicationServerResultCode.valueOf(rc.intValue()),
           rc);
      assertEquals(AssuredReplicationServerResultCode.valueOf(rc.name()),
           rc);
    }

    // Test the integer valueOf method with an undefined value.
    assertNull(AssuredReplicationServerResultCode.valueOf(1234));

    // Test the string valueOf method with an undefined value.
    try
    {
      AssuredReplicationServerResultCode.valueOf("undefined");
      fail("Expected an exception when trying to invoke valueOf with an " +
           "undefined value");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }
}
