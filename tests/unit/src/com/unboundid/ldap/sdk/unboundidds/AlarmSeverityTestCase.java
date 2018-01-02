/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the alarm severity enum.
 */
public final class AlarmSeverityTestCase
     extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the severity values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSeverityValues()
         throws Exception
  {
    for (final AlarmSeverity s : AlarmSeverity.values())
    {
      assertNotNull(s.name());
      assertNotNull(s.toString());

      assertEquals(AlarmSeverity.valueOf(s.name()), s);
      assertEquals(AlarmSeverity.forName(s.name()), s);
      assertEquals(AlarmSeverity.forName(s.name().toLowerCase()), s);
    }

    assertNull(AlarmSeverity.forName("does-not-exist"));

    try
    {
      AlarmSeverity.valueOf("does-not-exist");
      fail("Expected an exception for valueOf with an invalid value");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }
}
