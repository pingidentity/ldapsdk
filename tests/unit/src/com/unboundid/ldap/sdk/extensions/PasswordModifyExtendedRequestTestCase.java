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
package com.unboundid.ldap.sdk.extensions;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;

import static com.unboundid.util.StaticUtils.toUTF8String;



/**
 * This class provides a set of test cases for the PasswordModifyExtendedRequest
 * class.
 */
public class PasswordModifyExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest("newPassword");
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNull(r.getOldPassword());
    assertNull(r.getOldPasswordBytes());
    assertNull(r.getRawOldPassword());

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the first constructor with a {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Null()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest((String) null);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNull(r.getOldPassword());
    assertNull(r.getOldPasswordBytes());
    assertNull(r.getRawOldPassword());

    assertNull(r.getNewPassword());
    assertNull(r.getNewPasswordBytes());
    assertNull(r.getRawNewPassword());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest("newPassword".getBytes("UTF-8"));
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNull(r.getOldPassword());
    assertNull(r.getOldPasswordBytes());
    assertNull(r.getRawOldPassword());

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with a {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Null()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest((byte[]) null);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNull(r.getOldPassword());
    assertNull(r.getOldPasswordBytes());
    assertNull(r.getRawOldPassword());

    assertNull(r.getNewPassword());
    assertNull(r.getNewPasswordBytes());
    assertNull(r.getRawNewPassword());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the third constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest("oldPassword", "newPassword");
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the third constructor with a {@code null} oldPassword argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullOldPassword()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(null, "newPassword");
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNull(r.getOldPassword());
    assertNull(r.getOldPasswordBytes());
    assertNull(r.getRawOldPassword());

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the third constructor with a {@code null} newPassword argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullNewPassword()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest("oldPassword", null);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNull(r.getNewPassword());
    assertNull(r.getNewPasswordBytes());
    assertNull(r.getRawNewPassword());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the fourth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest("oldPassword".getBytes("UTF-8"),
                                           "newPassword".getBytes("UTF-8"));
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the fourth constructor with a {@code null} oldPassword argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullOldPassword()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(null,
                                           "newPassword".getBytes("UTF-8"));
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNull(r.getOldPassword());
    assertNull(r.getOldPasswordBytes());
    assertNull(r.getRawOldPassword());

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the fourth constructor with a {@code null} newPassword argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullNewPassword()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest("oldPassword".getBytes("UTF-8"),
                                           null);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNull(r.getNewPassword());
    assertNull(r.getNewPasswordBytes());
    assertNull(r.getRawNewPassword());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the fifth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com", "oldPassword",
                  "newPassword");
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the fifth constructor with a {@code null} user identity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NullUserIdentity()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(null, "oldPassword", "newPassword");
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the fifth constructor with a {@code null} old password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NullOldPassword()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com", null,
                  "newPassword");
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNull(r.getOldPassword());
    assertNull(r.getOldPasswordBytes());
    assertNull(r.getRawOldPassword());

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the fifth constructor with a {@code null} new password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NullNewPassword()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com", "oldPassword",
                  null);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNull(r.getNewPassword());
    assertNull(r.getNewPasswordBytes());
    assertNull(r.getRawNewPassword());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the sixth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com",
                  "oldPassword".getBytes("UTF-8"),
                  "newPassword".getBytes("UTF-8"));
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the sixth constructor with a {@code null} user identity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6NullUserIdentity()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(null,
                                           "oldPassword".getBytes("UTF-8"),
                                           "newPassword".getBytes("UTF-8"));
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the sixth constructor with a {@code null} old password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6NullOldPassword()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com", null,
                  "newPassword".getBytes("UTF-8"));
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNull(r.getOldPassword());
    assertNull(r.getOldPasswordBytes());
    assertNull(r.getRawOldPassword());

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the sixth constructor with a {@code null} new password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6NullNewPassword()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com",
                  "oldPassword".getBytes("UTF-8"), null);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNull(r.getNewPassword());
    assertNull(r.getNewPasswordBytes());
    assertNull(r.getRawNewPassword());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the seventh constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com", "oldPassword",
                  "newPassword", controls);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the seventh constructor with a {@code null} user identity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7NullUserIdentity()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(null, "oldPassword", "newPassword",
                                           controls);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the seventh constructor with a {@code null} old password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7NullOldPassword()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com", null,
                  "newPassword", controls);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNull(r.getOldPassword());
    assertNull(r.getOldPasswordBytes());
    assertNull(r.getRawOldPassword());

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the seventh constructor with a {@code null} new password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7NullNewPassword()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com", "oldPassword",
                  null, controls);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNull(r.getNewPassword());
    assertNull(r.getNewPasswordBytes());
    assertNull(r.getRawNewPassword());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the seventh constructor with a {@code null} set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7NullControls()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com", "oldPassword",
                  "newPassword", null);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the eighth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com",
                  "oldPassword".getBytes("UTF-8"),
                  "newPassword".getBytes("UTF-8"), controls);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the eighth constructor with a {@code null} user identity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8NullUserIdentity()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(null,
                                           "oldPassword".getBytes("UTF-8"),
                                           "newPassword".getBytes("UTF-8"),
                                           controls);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNull(r.getUserIdentity());

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the eighth constructor with a {@code null} old password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8NullOldPassword()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com", null,
                  "newPassword".getBytes("UTF-8"), controls);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNull(r.getOldPassword());
    assertNull(r.getOldPasswordBytes());
    assertNull(r.getRawOldPassword());

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the eighth constructor with a {@code null} new password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8NullNewPassword()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com",
                  "oldPassword".getBytes("UTF-8"), null, controls);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNull(r.getNewPassword());
    assertNull(r.getNewPasswordBytes());
    assertNull(r.getRawNewPassword());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the eighth constructor with a {@code null} set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8NullControls()
         throws Exception
  {
    PasswordModifyExtendedRequest r =
         new PasswordModifyExtendedRequest(
                  "uid=test.user,ou=People,dc=example,dc=com",
                  "oldPassword".getBytes("UTF-8"),
                  "newPassword".getBytes("UTF-8"), null);
    r = new PasswordModifyExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());

    assertNotNull(r.getValue());

    assertNotNull(r.getUserIdentity());
    assertEquals(r.getUserIdentity(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getOldPassword());
    assertEquals(r.getOldPassword(), "oldPassword");

    assertNotNull(r.getOldPasswordBytes());
    assertEquals(toUTF8String(r.getOldPasswordBytes()), "oldPassword");

    assertNotNull(r.getRawOldPassword());
    assertEquals(r.getRawOldPassword().stringValue(), "oldPassword");

    assertNotNull(r.getNewPassword());
    assertEquals(r.getNewPassword(), "newPassword");

    assertNotNull(r.getNewPasswordBytes());
    assertEquals(toUTF8String(r.getNewPasswordBytes()), "newPassword");

    assertNotNull(r.getRawNewPassword());
    assertEquals(r.getRawNewPassword().stringValue(), "newPassword");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the ninth constructor with a generic request containing no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor9NoValue()
         throws Exception
  {
    new PasswordModifyExtendedRequest(new ExtendedRequest("1.2.3.4"));
  }



  /**
   * Tests the ninth constructor with a generic request containing an invalid
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor9InvalidValue()
         throws Exception
  {
    new PasswordModifyExtendedRequest(
             new ExtendedRequest("1.2.3.4", new ASN1OctetString("foo")));
  }



  /**
   * Tests the ability to change a user password using the password modify
   * extended operation.  The user identity, old password, and new password will
   * all be included.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangePasswordAllFields()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.add("dn: uid=test.user," + getTestBaseDN(),
             "objectClass: top",
             "objectclass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: oldPassword",
             "ds-privilege-name: bypass-acl");

    try
    {
      PasswordModifyExtendedRequest request =
           new PasswordModifyExtendedRequest("uid=test.user," + getTestBaseDN(),
                                             "oldPassword", "newPassword");
      PasswordModifyExtendedResult result = request.process(conn, 1);

      assertNotNull(result);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);

      assertNull(result.getGeneratedPassword());
      assertNull(result.getGeneratedPasswordBytes());
      assertNull(result.getRawGeneratedPassword());

      assertNotNull(result.toString());
    }
    finally
    {
      try
      {
        conn.delete("uid=test.user," + getTestBaseDN());
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
    }
  }



  /**
   * Tests the ability to change a user password using the password modify
   * extended operation.  The user identity and old password will be included
   * but the new password will not (so the server should generate one and
   * include it in the response).
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangePasswordNoNewPassword()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.add("dn: uid=test.user," + getTestBaseDN(),
             "objectClass: top",
             "objectclass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: oldPassword",
             "ds-privilege-name: bypass-acl");

    try
    {
      PasswordModifyExtendedRequest request =
           new PasswordModifyExtendedRequest("uid=test.user," + getTestBaseDN(),
                                             "oldPassword", null);
      PasswordModifyExtendedResult result = request.process(conn, 1);

      assertNotNull(result);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);

      assertNotNull(result.getGeneratedPassword());
      assertNotNull(result.getGeneratedPasswordBytes());
      assertNotNull(result.getRawGeneratedPassword());

      assertNotNull(result.toString());
    }
    finally
    {
      try
      {
        conn.delete("uid=test.user," + getTestBaseDN());
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
    }
  }
}
