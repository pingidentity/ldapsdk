/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;



/**
 * This class provides test coverage for the in-memory directory server's
 * support for the password modify extended operation.
 */
public final class InMemoryDirectoryServerPasswordModifyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the password modify operation when requested
   * by an unauthenticated client.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnauthenticated()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    // Verify that an unauthenticated attempt will fail without a user identity.
    PasswordModifyExtendedResult result = (PasswordModifyExtendedResult)
         conn.processExtendedOperation(new PasswordModifyExtendedRequest(
              null, null, "pw1"));
    assertEquals(result.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    // Verify that an unauthenticated attempt will fail without an old password.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com", null, "pw1"));
    assertEquals(result.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    // Verify that an unauthenticated attempt will fail with the wrong old
    // password.
    result = (PasswordModifyExtendedResult)
         conn.processExtendedOperation(new PasswordModifyExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com", "wrongPassword",
              "newPassword"));
    assertEquals(result.getResultCode(), ResultCode.INVALID_CREDENTIALS);

    // Verify that an unauthenticated attempt will succeed with the right old
    // password.
    result = (PasswordModifyExtendedResult)
         conn.processExtendedOperation(new PasswordModifyExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com", "password",
              "newPassword"));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNull(result.getGeneratedPassword());

    // Verify that it is possible to generate a new password.
    result = (PasswordModifyExtendedResult)
         conn.processExtendedOperation(new PasswordModifyExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com", "newPassword",
              null));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNotNull(result.getGeneratedPassword());

    conn.close();
  }



  /**
   * Provides test coverage for the password modify operation when requested
   * by a client authenticated as a normal user.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthenticatedAsNormalUser()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ds.add(
         "dn: uid=another.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: another.user",
         "givenName: Another",
         "sn: User",
         "cn: Another User",
         "userPassword: password");

    final LDAPConnection conn = ds.getConnection();
    conn.bind("uid=test.user,ou=People,dc=example,dc=com", "password");

    // Verify that the attempt will succeed for the authenticated user when
    // supplied only with a new password.
    PasswordModifyExtendedResult result = (PasswordModifyExtendedResult)
         conn.processExtendedOperation(new PasswordModifyExtendedRequest(
              "newPassword1"));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt will fail for the authenticated user when
    // supplied with both old and new passwords and the old password is wrong.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest("wrongPassword", "newPassword2"));
    assertEquals(result.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt will succeed for the authenticated user when
    // supplied with both old and new passwords and the old password is correct.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest("newPassword1", "newPassword2"));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt to change the password for the authenticated
    // user can successfully generate a new password.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest((String) null));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNotNull(result.getGeneratedPassword());

    // Verify that the attempt to change the password will succeed for a
    // different regular user when the identity is provided as a DN.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest(
              "uid=another.user,ou=People,dc=example,dc=com", null,
              "newPassword1"));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt to change the password will succeed for a
    // different regular user when the identity is provided as an authzID.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest("u:another.user", null,
              "newPassword2"));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt to change the password will fail for a
    // different regular user when the identity is provided as a malformed
    // authzID.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest("dn:malformed", null,
              "newPassword2"));
    assertEquals(result.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt to change the password will fail for a target
    // user that is an additional bind user.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest("dn:cn=Directory Manager", null,
              "newPassword3"));
    assertEquals(result.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt to change the password will fail for a target
    // user that does not exist.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest("cn=missing,dc=example,dc=com", null,
              "newPassword4"));
    assertEquals(result.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    assertNull(result.getGeneratedPassword());

    conn.close();
  }



  /**
   * Provides test coverage for the password modify operation when requested
   * by a client authenticated as an additional bind user.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthenticatedAsAdditionalBindUser()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ds.add(
         "dn: uid=another.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: another.user",
         "givenName: Another",
         "sn: User",
         "cn: Another User",
         "userPassword: password");

    final LDAPConnection conn = ds.getConnection();
    conn.bind("cn=Directory Manager", "password");

    // Verify that the attempt will fail for the authenticated user when
    // supplied only with a new password.
    PasswordModifyExtendedResult result = (PasswordModifyExtendedResult)
         conn.processExtendedOperation(new PasswordModifyExtendedRequest(
              "newPassword1"));
    assertEquals(result.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt will fail for the authenticated user when
    // supplied with both old and new passwords and the old password is wrong.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest("wrongPassword", "newPassword2"));
    assertEquals(result.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt will fail for the authenticated user when
    // supplied with both old and new passwords and the old password is correct.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest("password", "newPassword2"));
    assertEquals(result.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt to change the password will succeed for a
    // different regular user when the identity is provided as a DN.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest(
              "uid=another.user,ou=People,dc=example,dc=com", null,
              "newPassword1"));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt to change the password will succeed for a
    // different regular user when the identity is provided as an authzID.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest("u:another.user", null,
              "newPassword2"));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNull(result.getGeneratedPassword());

    // Verify that the attempt to change the password will fail for a target
    // user that does not exist.
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest("cn=missing,dc=example,dc=com", null,
              "newPassword4"));
    assertEquals(result.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    assertNull(result.getGeneratedPassword());

    conn.close();
  }



  /**
   * Tests the behavior of the extended operation with request controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControls()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();
    conn.bind("uid=test.user,ou=People,dc=example,dc=com", "password");

    // Verify that the attempt to change the password will fail with a
    // critical control.
    Control[] controls = { new Control("1.2.3.4", true) };
    PasswordModifyExtendedResult result = (PasswordModifyExtendedResult)
         conn.processExtendedOperation(new PasswordModifyExtendedRequest(
              null, null, "newPassword", controls));
    assertEquals(result.getResultCode(),
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);

    // Verify that the attempt will succeed with only non-critical controls.
    controls = new Control[] { new Control("1.2.3.4", false) };
    result = (PasswordModifyExtendedResult) conn.processExtendedOperation(
         new PasswordModifyExtendedRequest(null, null, "newPassword",
              controls));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    conn.close();
  }



  /**
   * Provides test coverage for the password modify operation when the request
   * is malformed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedRequest()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();
    conn.bind("uid=test.user,ou=People,dc=example,dc=com", "password");

    try
    {
      conn.processExtendedOperation(new ExtendedRequest(
           PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID,
           new ASN1OctetString("foo")));
    }
    catch (final LDAPException le)
    {
      assertFalse(le.getResultCode().equals(ResultCode.SUCCESS));
    }

    conn.close();
  }
}
