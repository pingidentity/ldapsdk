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
package com.unboundid.ldap.sdk.experimental;



import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * DraftBeheraLDAPPasswordPolicy10WarningType enum.
 */
public class DraftBeheraLDAPPasswordPolicy10WarningTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code TIME_BEFORE_EXPIRATION} element.
   */
  @Test()
  public void testTimeBeforeExpiration()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10WarningType.TIME_BEFORE_EXPIRATION.
              getName(),
         "time before expiration");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10WarningType.TIME_BEFORE_EXPIRATION.
              toString(),
         "time before expiration");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10WarningType.
              valueOf("TIME_BEFORE_EXPIRATION"),
         DraftBeheraLDAPPasswordPolicy10WarningType.TIME_BEFORE_EXPIRATION);
  }



  /**
   * Tests the {@code GRACE_LOGINS_REMAINING} element.
   */
  @Test()
  public void testGraceLoginsRemaining()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10WarningType.GRACE_LOGINS_REMAINING.
              getName(),
         "grace logins remaining");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10WarningType.GRACE_LOGINS_REMAINING.
              toString(),
         "grace logins remaining");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10WarningType.
              valueOf("GRACE_LOGINS_REMAINING"),
         DraftBeheraLDAPPasswordPolicy10WarningType.GRACE_LOGINS_REMAINING);
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    TreeSet<DraftBeheraLDAPPasswordPolicy10WarningType> expectedTypes =
         new TreeSet<DraftBeheraLDAPPasswordPolicy10WarningType>();
    expectedTypes.add(
         DraftBeheraLDAPPasswordPolicy10WarningType.TIME_BEFORE_EXPIRATION);
    expectedTypes.add(
         DraftBeheraLDAPPasswordPolicy10WarningType.GRACE_LOGINS_REMAINING);

    TreeSet<DraftBeheraLDAPPasswordPolicy10WarningType> gotTypes =
         new TreeSet<DraftBeheraLDAPPasswordPolicy10WarningType>();
    for (DraftBeheraLDAPPasswordPolicy10WarningType wt :
         DraftBeheraLDAPPasswordPolicy10WarningType.values())
    {
      gotTypes.add(wt);
    }

    assertEquals(gotTypes, expectedTypes);
  }
}
