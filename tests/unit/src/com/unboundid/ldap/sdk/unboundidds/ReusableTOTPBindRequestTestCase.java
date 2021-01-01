/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import java.util.ArrayList;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the reusable variant of the
 * TOTP bind request.
 */
public final class ReusableTOTPBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the minimal constructor and no static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoStaticStringPassword()
         throws Exception
  {
    ReusableTOTPBindRequest r = new ReusableTOTPBindRequest("u:john.doe",
         null, "12345678901234567890".getBytes(), (String) null);

    r = r.duplicate();
    assertNotNull(r);

    r = r.getRebindRequest("127.0.0.1", 389);
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-TOTP");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:john.doe");

    assertNull(r.getAuthorizationID());

    assertNull(r.getStaticPassword());

    assertNotNull(r.getSharedSecret());
    assertEquals(r.getSharedSecret(), "12345678901234567890".getBytes());

    assertEquals(r.getTOTPIntervalDurationSeconds(), 30);

    assertEquals(r.getTOTPNumDigits(), 6);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertNotNull(r.getSASLCredentials());
    final SingleUseTOTPBindRequest sr =
         SingleUseTOTPBindRequest.decodeSASLCredentials(r.getSASLCredentials(),
              r.getControls());
    assertNotNull(sr);
    assertEquals(sr.getAuthenticationID(), "u:john.doe");
    assertNull(sr.getAuthorizationID());
    assertNull(sr.getStaticPassword());
    assertNotNull(sr.getTOTPPassword());
  }



  /**
   * Provides test coverage for the full constructor with a string static
   * password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithStaticStringPassword()
         throws Exception
  {
    ReusableTOTPBindRequest r = new ReusableTOTPBindRequest("u:john.doe",
         "u:authz.user", "12345678901234567890".getBytes(), "password",
         60, 8, new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = r.duplicate();
    assertNotNull(r);

    r = r.getRebindRequest("127.0.0.1", 389);
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-TOTP");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:john.doe");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:authz.user");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNotNull(r.getSharedSecret());
    assertEquals(r.getSharedSecret(), "12345678901234567890".getBytes());

    assertEquals(r.getTOTPIntervalDurationSeconds(), 60);

    assertEquals(r.getTOTPNumDigits(), 8);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertNotNull(r.getSASLCredentials());
    final SingleUseTOTPBindRequest sr =
         SingleUseTOTPBindRequest.decodeSASLCredentials(r.getSASLCredentials(),
              r.getControls());
    assertNotNull(sr);
    assertEquals(sr.getAuthenticationID(), "u:john.doe");
    assertEquals(sr.getAuthorizationID(), "u:authz.user");
    assertEquals(sr.getStaticPassword().stringValue(), "password");
    assertNotNull(sr.getTOTPPassword());
  }



  /**
   * Provides test coverage for the minimal constructor and no static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoStaticByteArrayPassword()
         throws Exception
  {
    ReusableTOTPBindRequest r = new ReusableTOTPBindRequest("u:john.doe",
         null, "12345678901234567890".getBytes(), (byte[]) null);

    r = r.duplicate();
    assertNotNull(r);

    r = r.getRebindRequest("127.0.0.1", 389);
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-TOTP");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:john.doe");

    assertNull(r.getAuthorizationID());

    assertNull(r.getStaticPassword());

    assertNotNull(r.getSharedSecret());
    assertEquals(r.getSharedSecret(), "12345678901234567890".getBytes());

    assertEquals(r.getTOTPIntervalDurationSeconds(), 30);

    assertEquals(r.getTOTPNumDigits(), 6);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertNotNull(r.getSASLCredentials());
    final SingleUseTOTPBindRequest sr =
         SingleUseTOTPBindRequest.decodeSASLCredentials(r.getSASLCredentials(),
              r.getControls());
    assertNotNull(sr);
    assertEquals(sr.getAuthenticationID(), "u:john.doe");
    assertNull(sr.getAuthorizationID());
    assertNull(sr.getStaticPassword());
    assertNotNull(sr.getTOTPPassword());
  }



  /**
   * Provides test coverage for the full constructor with a byte array static
   * password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithStaticByteArrayPassword()
         throws Exception
  {
    ReusableTOTPBindRequest r = new ReusableTOTPBindRequest("u:john.doe",
         "u:authz.user", "12345678901234567890".getBytes(),
         "password".getBytes(), 60, 8, new Control("1.2.3.4"),
         new Control("1.2.3.5"));

    r = r.duplicate();
    assertNotNull(r);

    r = r.getRebindRequest("127.0.0.1", 389);
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-TOTP");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:john.doe");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:authz.user");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNotNull(r.getSharedSecret());
    assertEquals(r.getSharedSecret(), "12345678901234567890".getBytes());

    assertEquals(r.getTOTPIntervalDurationSeconds(), 60);

    assertEquals(r.getTOTPNumDigits(), 8);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertNotNull(r.getSASLCredentials());
    final SingleUseTOTPBindRequest sr =
         SingleUseTOTPBindRequest.decodeSASLCredentials(r.getSASLCredentials(),
              r.getControls());
    assertNotNull(sr);
    assertEquals(sr.getAuthenticationID(), "u:john.doe");
    assertEquals(sr.getAuthorizationID(), "u:authz.user");
    assertEquals(sr.getStaticPassword().stringValue(), "password");
    assertNotNull(sr.getTOTPPassword());
  }



  /**
   * Tests the constructor that takes a string static password with an
   * invalid interval duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testInvalidIntervalDurationStringPassword()
         throws Exception
  {
    new ReusableTOTPBindRequest("u:john.doe", null,
         "12345678901234567890".getBytes(), "password", 0, 6);
  }



  /**
   * Tests the constructor that takes a byte array static password with an
   * invalid interval duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testInvalidIntervalDurationByteArrayPassword()
         throws Exception
  {
    new ReusableTOTPBindRequest("u:john.doe", null,
         "12345678901234567890".getBytes(), "password".getBytes(), 0, 6);
  }



  /**
   * Tests the constructor that takes a string static password with an invalid
   * number of digits.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testInvalidNumDigitsStringPassword()
         throws Exception
  {
    new ReusableTOTPBindRequest("u:john.doe", null,
         "12345678901234567890".getBytes(), "password", 30, 5);
  }



  /**
   * Tests the constructor that takes a byte array static password with an
   * invalid number of digits.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testInvalidNumDigitsByteArrayPassword()
         throws Exception
  {
    new ReusableTOTPBindRequest("u:john.doe", null,
         "12345678901234567890".getBytes(), "password".getBytes(), 30, 5);
  }
}
