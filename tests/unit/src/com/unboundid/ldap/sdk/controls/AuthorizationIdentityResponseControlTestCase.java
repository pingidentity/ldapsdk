/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the
 * AuthorizationIdentityResponseControl class.
 */
public class AuthorizationIdentityResponseControlTestCase
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
    new AuthorizationIdentityResponseControl();
  }



  /**
   * Tests the second constructor with a non-empty authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    String authzID = "dn:uid=test.user,ou=People,dc=example,dc=com";

    AuthorizationIdentityResponseControl c =
         new AuthorizationIdentityResponseControl(authzID);

    assertFalse(c.isCritical());

    assertEquals(c.getAuthorizationID(), authzID);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with an empty authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2EmptyAuthzID()
         throws Exception
  {
    String authzID = "";

    AuthorizationIdentityResponseControl c =
         new AuthorizationIdentityResponseControl(authzID);

    assertFalse(c.isCritical());

    assertEquals(c.getAuthorizationID(), authzID);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a {@code null} authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullAuthzID()
         throws Exception
  {
    new AuthorizationIdentityResponseControl(null);
  }



  /**
   * Tests the third constructor with a valid set of information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    String authzID = "dn:uid=test.user,ou=People,dc=example,dc=com";

    AuthorizationIdentityResponseControl c =
         new AuthorizationIdentityResponseControl("2.16.84.1.113730.3.4.15",
                  true, new ASN1OctetString(authzID));

    assertTrue(c.isCritical());
    assertEquals(c.getAuthorizationID(), authzID);
    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NullValue()
         throws Exception
  {
    new AuthorizationIdentityResponseControl("2.16.84.1.113730.3.4.15", true,
                                             null);
  }



  /**
   * Tests the {@code get} method with a result that does not contain an
   * authorization identity response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final AuthorizationIdentityResponseControl c =
         AuthorizationIdentityResponseControl.get(r);
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
      new AuthorizationIdentityResponseControl("dn:cn=Directory Manager")
    };

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final AuthorizationIdentityResponseControl c =
         AuthorizationIdentityResponseControl.get(r);
    assertNotNull(c);
    assertEquals(c.getAuthorizationID(), "dn:cn=Directory Manager");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as an authorization identity
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp =
         new AuthorizationIdentityResponseControl("dn:cn=Directory Manager");

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final AuthorizationIdentityResponseControl c =
         AuthorizationIdentityResponseControl.get(r);
    assertNotNull(c);
    assertEquals(c.getAuthorizationID(), "dn:cn=Directory Manager");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as an authorization
   * identity response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(
           AuthorizationIdentityResponseControl.
                AUTHORIZATION_IDENTITY_RESPONSE_OID,
           false, null)
    };

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    AuthorizationIdentityResponseControl.get(r);
  }
}
