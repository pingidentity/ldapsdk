/*
 * Copyright 2007-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2017 Ping Identity Corporation
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



import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the PasswordPolicyWarningType
 * enum.
 */
public class PasswordPolicyWarningTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code TIME_BEFORE_EXPIRATION} element.
   */
  @Test()
  public void testTimeBeforeExpiration()
  {
    assertEquals(PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION.getName(),
                 "time before expiration");

    assertEquals(PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION.toString(),
                 "time before expiration");

    assertEquals(PasswordPolicyWarningType.valueOf("TIME_BEFORE_EXPIRATION"),
                 PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION);
  }



  /**
   * Tests the {@code GRACE_LOGINS_REMAINING} element.
   */
  @Test()
  public void testGraceLoginsRemaining()
  {
    assertEquals(PasswordPolicyWarningType.GRACE_LOGINS_REMAINING.getName(),
                 "grace logins remaining");

    assertEquals(PasswordPolicyWarningType.GRACE_LOGINS_REMAINING.toString(),
                 "grace logins remaining");

    assertEquals(PasswordPolicyWarningType.valueOf("GRACE_LOGINS_REMAINING"),
                 PasswordPolicyWarningType.GRACE_LOGINS_REMAINING);
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    TreeSet<PasswordPolicyWarningType> expectedTypes =
         new TreeSet<PasswordPolicyWarningType>();
    expectedTypes.add(PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION);
    expectedTypes.add(PasswordPolicyWarningType.GRACE_LOGINS_REMAINING);

    TreeSet<PasswordPolicyWarningType> gotTypes =
         new TreeSet<PasswordPolicyWarningType>();
    for (PasswordPolicyWarningType wt : PasswordPolicyWarningType.values())
    {
      gotTypes.add(wt);
    }

    assertEquals(gotTypes, expectedTypes);
  }
}
