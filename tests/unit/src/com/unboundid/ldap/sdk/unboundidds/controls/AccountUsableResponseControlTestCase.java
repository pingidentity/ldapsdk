/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2008-2021 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchResultEntry;



/**
 * This class provides a set of test cases for the
 * {@code AccountUsableResponseControl} class.
 */
public class AccountUsableResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first public constructor with a positive number of seconds until
   * expiration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void Constructor1Positive()
         throws Exception
  {
    AccountUsableResponseControl c = new AccountUsableResponseControl(1234);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertTrue(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), 1234);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertTrue(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first public constructor with zero seconds until expiration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Zero()
         throws Exception
  {
    AccountUsableResponseControl c = new AccountUsableResponseControl(0);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertTrue(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), 0);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertTrue(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first public constructor with a negative number of seconds until
   * expiration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Negative()
         throws Exception
  {
    AccountUsableResponseControl c = new AccountUsableResponseControl(-1234);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertTrue(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertTrue(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor to indicate that the account is
   * inactive.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Inactive()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(true, false, false, -1, -1);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertTrue(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertFalse(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor to indicate that the user must change
   * their password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MustChange()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(false, true, false, -1, -1);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertFalse(c.isInactive());
    assertTrue(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertFalse(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor to indicate that the password is
   * expired.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2PasswordExpired()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(false, false, true, -1, -1);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertTrue(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertFalse(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor with a positive number of remaining
   * grace logins.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2PositiveRemainingGraceLogins()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(false, false, false, 1234, -1);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), 1234);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertFalse(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor with zero remaining grace logins.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2ZeroRemainingGraceLogins()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(false, false, false, 0, -1);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), 0);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertFalse(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor with a negative number of remaining
   * grace logins.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NegativeRemainingGraceLogins()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(false, false, false, -1234, -1);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertTrue(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor with a positive number of seconds until
   * unlock.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2PositiveSecondsUntilUnlock()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(false, false, false, -1, 1234);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), 1234);

    assertNotNull(c.getUnusableReasons());
    assertFalse(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor with zero seconds until unlock.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2ZeroSecondsUntilUnlock()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(false, false, false, -1, 0);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), 0);

    assertNotNull(c.getUnusableReasons());
    assertTrue(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor with a negative number of seconds until
   * unlock.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NegativeSecondsUntilUnlock()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(false, false, false, -1, -1234);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertTrue(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor with all elements using their default
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2AllDefault()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(false, false, false, -1, -1);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertFalse(c.isInactive());
    assertFalse(c.mustChangePassword());
    assertFalse(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), -1);
    assertEquals(c.getSecondsUntilUnlock(), -1);

    assertNotNull(c.getUnusableReasons());
    assertTrue(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second public constructor with all elements using non-default
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoneDefault()
         throws Exception
  {
    AccountUsableResponseControl c =
         new AccountUsableResponseControl(true, true, true, 1234, 1234);
    c = new AccountUsableResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertFalse(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), -1);

    assertTrue(c.isInactive());
    assertTrue(c.mustChangePassword());
    assertTrue(c.passwordIsExpired());
    assertEquals(c.getRemainingGraceLogins(), 1234);
    assertEquals(c.getSecondsUntilUnlock(), 1234);

    assertNotNull(c.getUnusableReasons());
    assertFalse(c.getUnusableReasons().isEmpty());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code get} method with a result that does not contain an account
   * usable response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final AccountUsableResponseControl c = AccountUsableResponseControl.get(e);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new AccountUsableResponseControl(1234)
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final AccountUsableResponseControl c = AccountUsableResponseControl.get(e);
    assertNotNull(c);

    assertTrue(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), 1234);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as an account usable response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new AccountUsableResponseControl(1234);

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final AccountUsableResponseControl c = AccountUsableResponseControl.get(e);
    assertNotNull(c);

    assertTrue(c.isUsable());

    assertEquals(c.getSecondsUntilExpiration(), 1234);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as an account usable
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(AccountUsableResponseControl.ACCOUNT_USABLE_RESPONSE_OID,
           false, null)
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    AccountUsableResponseControl.get(e);
  }
}
