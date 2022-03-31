/*
 * Copyright 2008-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2022 Ping Identity Corporation
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
 * Copyright (C) 2008-2022 Ping Identity Corporation
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
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



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



  /**
   * Tests the behavior when trying to encode and decode the control to and from
   * a JSON object when the account is usable and password expiration is not
   * enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAccountUsableExpirationNotEnabled()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 4);

    assertEquals(valueObject.getFieldAsBoolean("account-is-usable"),
         Boolean.TRUE);

    assertFalse(valueObject.hasField("seconds-until-password-expiration"));

    assertEquals(valueObject.getFieldAsBoolean("account-is-inactive"),
         Boolean.FALSE);

    assertEquals(valueObject.getFieldAsBoolean("must-change-password"),
         Boolean.FALSE);

    assertEquals(valueObject.getFieldAsBoolean("password-is-expired"),
         Boolean.FALSE);

    assertFalse(valueObject.hasField("remaining-grace-logins"));

    assertFalse(valueObject.hasField("seconds-until-unlock"));


    AccountUsableResponseControl decodedControl =
         AccountUsableResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.isUsable());

    assertEquals(decodedControl.getSecondsUntilExpiration(), -1);

    assertFalse(decodedControl.isInactive());

    assertFalse(decodedControl.mustChangePassword());

    assertFalse(decodedControl.passwordIsExpired());

    assertEquals(decodedControl.getRemainingGraceLogins(), -1);

    assertEquals(decodedControl.getSecondsUntilUnlock(), -1);


    decodedControl =
         (AccountUsableResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.isUsable());

    assertEquals(decodedControl.getSecondsUntilExpiration(), -1);

    assertFalse(decodedControl.isInactive());

    assertFalse(decodedControl.mustChangePassword());

    assertFalse(decodedControl.passwordIsExpired());

    assertEquals(decodedControl.getRemainingGraceLogins(), -1);

    assertEquals(decodedControl.getSecondsUntilUnlock(), -1);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and from
   * a JSON object when the account is usable and password expiration is
   * enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAccountUsableExpirationEnabled()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(12345);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 5);

    assertEquals(valueObject.getFieldAsBoolean("account-is-usable"),
         Boolean.TRUE);

    assertEquals(
         valueObject.getFieldAsInteger("seconds-until-password-expiration"),
         Integer.valueOf(12345));

    assertEquals(valueObject.getFieldAsBoolean("account-is-inactive"),
         Boolean.FALSE);

    assertEquals(valueObject.getFieldAsBoolean("must-change-password"),
         Boolean.FALSE);

    assertEquals(valueObject.getFieldAsBoolean("password-is-expired"),
         Boolean.FALSE);

    assertFalse(valueObject.hasField("remaining-grace-logins"));

    assertFalse(valueObject.hasField("seconds-until-unlock"));


    AccountUsableResponseControl decodedControl =
         AccountUsableResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.isUsable());

    assertEquals(decodedControl.getSecondsUntilExpiration(), 12345);

    assertFalse(decodedControl.isInactive());

    assertFalse(decodedControl.mustChangePassword());

    assertFalse(decodedControl.passwordIsExpired());

    assertEquals(decodedControl.getRemainingGraceLogins(), -1);

    assertEquals(decodedControl.getSecondsUntilUnlock(), -1);


    decodedControl =
         (AccountUsableResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.isUsable());

    assertEquals(decodedControl.getSecondsUntilExpiration(), 12345);

    assertFalse(decodedControl.isInactive());

    assertFalse(decodedControl.mustChangePassword());

    assertFalse(decodedControl.passwordIsExpired());

    assertEquals(decodedControl.getRemainingGraceLogins(), -1);

    assertEquals(decodedControl.getSecondsUntilUnlock(), -1);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and from
   * a JSON object when the account is not usable and no grace logins or
   * unlock time information is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAccountNotUsableNoGraceLoginsOrSecsUntilUnlock()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(true, false, true, -1, -1);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 4);

    assertEquals(valueObject.getFieldAsBoolean("account-is-usable"),
         Boolean.FALSE);

    assertFalse(valueObject.hasField("seconds-until-password-expiration"));

    assertEquals(valueObject.getFieldAsBoolean("account-is-inactive"),
         Boolean.TRUE);

    assertEquals(valueObject.getFieldAsBoolean("must-change-password"),
         Boolean.FALSE);

    assertEquals(valueObject.getFieldAsBoolean("password-is-expired"),
         Boolean.TRUE);

    assertFalse(valueObject.hasField("remaining-grace-logins"));

    assertFalse(valueObject.hasField("seconds-until-unlock"));


    AccountUsableResponseControl decodedControl =
         AccountUsableResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertFalse(decodedControl.isUsable());

    assertEquals(decodedControl.getSecondsUntilExpiration(), -1);

    assertTrue(decodedControl.isInactive());

    assertFalse(decodedControl.mustChangePassword());

    assertTrue(decodedControl.passwordIsExpired());

    assertEquals(decodedControl.getRemainingGraceLogins(), -1);

    assertEquals(decodedControl.getSecondsUntilUnlock(), -1);


    decodedControl =
         (AccountUsableResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertFalse(decodedControl.isUsable());

    assertEquals(decodedControl.getSecondsUntilExpiration(), -1);

    assertTrue(decodedControl.isInactive());

    assertFalse(decodedControl.mustChangePassword());

    assertTrue(decodedControl.passwordIsExpired());

    assertEquals(decodedControl.getRemainingGraceLogins(), -1);

    assertEquals(decodedControl.getSecondsUntilUnlock(), -1);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and from
   * a JSON object when the account is not usable and both grace logins and
   * unlock time values are available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAccountNotUsableGraceLoginsAndSecsUntilUnlock()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(false, true, false, 1234, 5678);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 6);

    assertEquals(valueObject.getFieldAsBoolean("account-is-usable"),
         Boolean.FALSE);

    assertFalse(valueObject.hasField("seconds-until-password-expiration"));

    assertEquals(valueObject.getFieldAsBoolean("account-is-inactive"),
         Boolean.FALSE);

    assertEquals(valueObject.getFieldAsBoolean("must-change-password"),
         Boolean.TRUE);

    assertEquals(valueObject.getFieldAsBoolean("password-is-expired"),
         Boolean.FALSE);

    assertEquals(valueObject.getFieldAsInteger("remaining-grace-logins"),
         Integer.valueOf(1234));

    assertEquals(valueObject.getFieldAsInteger("seconds-until-unlock"),
         Integer.valueOf(5678));


    AccountUsableResponseControl decodedControl =
         AccountUsableResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertFalse(decodedControl.isUsable());

    assertEquals(decodedControl.getSecondsUntilExpiration(), -1);

    assertFalse(decodedControl.isInactive());

    assertTrue(decodedControl.mustChangePassword());

    assertFalse(decodedControl.passwordIsExpired());

    assertEquals(decodedControl.getRemainingGraceLogins(), 1234);

    assertEquals(decodedControl.getSecondsUntilUnlock(), 5678);


    decodedControl =
         (AccountUsableResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertFalse(decodedControl.isUsable());

    assertEquals(decodedControl.getSecondsUntilExpiration(), -1);

    assertFalse(decodedControl.isInactive());

    assertTrue(decodedControl.mustChangePassword());

    assertFalse(decodedControl.passwordIsExpired());

    assertEquals(decodedControl.getRemainingGraceLogins(), 1234);

    assertEquals(decodedControl.getSecondsUntilUnlock(), 5678);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when the
   * value was provided in the base64-encoded representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlBase64Value()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    final AccountUsableResponseControl decodedControl =
         AccountUsableResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.isUsable());

    assertEquals(decodedControl.getSecondsUntilExpiration(), -1);

    assertFalse(decodedControl.isInactive());

    assertFalse(decodedControl.mustChangePassword());

    assertFalse(decodedControl.passwordIsExpired());

    assertEquals(decodedControl.getRemainingGraceLogins(), -1);

    assertEquals(decodedControl.getSecondsUntilUnlock(), -1);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when the
   * value was provided in the JSON-encoded representation and the required
   * account-is-usable field was not provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueMissingAccountIsUsable()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-inactive", false),
              new JSONField("must-change-password", false),
              new JSONField("password-is-expired", false))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when the
   * value was provided in the JSON-encoded representation and the required
   * account-is-inactive field was not provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueMissingAccountIsInactive()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", true),
              new JSONField("must-change-password", false),
              new JSONField("password-is-expired", false))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when the
   * value was provided in the JSON-encoded representation and the required
   * must-change-password field was not provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueMissingMustChangePassword()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", true),
              new JSONField("account-is-inactive", false),
              new JSONField("password-is-expired", false))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when the
   * value was provided in the JSON-encoded representation and the required
   * password-is-expired field was not provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueMissingPasswordIsExpired()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", true),
              new JSONField("account-is-inactive", false),
              new JSONField("must-change-password", false))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when both
   * account-is-usable and account-is-inactive are both true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueAccountInactiveUsableConflict()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", true),
              new JSONField("account-is-inactive", true),
              new JSONField("must-change-password", false),
              new JSONField("password-is-expired", false))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when both
   * account-is-usable and must-change-password are both true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueMustChangePasswordUsableConflict()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", true),
              new JSONField("account-is-inactive", false),
              new JSONField("must-change-password", true),
              new JSONField("password-is-expired", false))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when both
   * account-is-usable and password-is-expired are both true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValuePasswordIsExpiredUsableConflict()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", true),
              new JSONField("account-is-inactive", false),
              new JSONField("must-change-password", false),
              new JSONField("password-is-expired", true))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when
   * account-is-usable is true and a remaining grace logins value is specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueUsableWithRemainingGraceLogins()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", true),
              new JSONField("account-is-inactive", false),
              new JSONField("must-change-password", false),
              new JSONField("password-is-expired", false),
              new JSONField("remaining-grace-logins", 3))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when
   * account-is-usable is true and a seconds until unlock value is specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueUsableWithSecondsUntilUnlock()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", true),
              new JSONField("account-is-inactive", false),
              new JSONField("must-change-password", false),
              new JSONField("password-is-expired", false),
              new JSONField("seconds-until-unlock", 12345))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when
   * account-is-usable is false and a seconds-until-password-expiration value is
   * specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueUnusableWithSecondsUntilExpiration()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", false),
              new JSONField("seconds-until-password-expiration", 12345),
              new JSONField("account-is-inactive", false),
              new JSONField("must-change-password", false),
              new JSONField("password-is-expired", true))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when
   * the value object has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueUnrecognizedFieldStrictMode()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", false),
              new JSONField("account-is-inactive", false),
              new JSONField("must-change-password", false),
              new JSONField("password-is-expired", true),
              new JSONField("unrecognized", "unrecognized"))));

    AccountUsableResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when decoding the control from a JSON object when
   * the value object has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlJSONValueUnrecognizedFieldNonStrictMode()
          throws Exception
  {
    final AccountUsableResponseControl c =
         new AccountUsableResponseControl(-1);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("account-is-usable", false),
              new JSONField("account-is-inactive", false),
              new JSONField("must-change-password", false),
              new JSONField("password-is-expired", true),
              new JSONField("unrecognized", "unrecognized"))));

    final AccountUsableResponseControl decodedControl =
         AccountUsableResponseControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertFalse(decodedControl.isUsable());

    assertEquals(decodedControl.getSecondsUntilExpiration(), -1);

    assertFalse(decodedControl.isInactive());

    assertFalse(decodedControl.mustChangePassword());

    assertTrue(decodedControl.passwordIsExpired());

    assertEquals(decodedControl.getRemainingGraceLogins(), -1);

    assertEquals(decodedControl.getSecondsUntilUnlock(), -1);
  }
}
