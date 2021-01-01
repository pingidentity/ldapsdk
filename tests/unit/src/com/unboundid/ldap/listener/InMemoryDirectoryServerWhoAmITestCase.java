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

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;



/**
 * This class provides test coverage for the in-memory directory server's
 * support for the "Who Am I?" extended operation.
 */
public final class InMemoryDirectoryServerWhoAmITestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for various "Who Am I?" scenarios.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWhoAmI()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    // Without authentication, the authorization identity should be anonymous.
    WhoAmIExtendedResult result = (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNotNull(result.getAuthorizationID());
    assertTrue(result.getAuthorizationID().equals("dn:"));


    // Authenticate as a normal user, and verify that the change is reflected in
    // the extended result.
    conn.bind("uid=test.user,ou=People,dc=example,dc=com", "password");

    result = (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNotNull(result.getAuthorizationID());
    assertTrue(result.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(result.getAuthorizationID().substring(3)),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Bind anonymously and verify that the identity is again anonymous
    conn.bind("", "");

    result = (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNotNull(result.getAuthorizationID());
    assertTrue(result.getAuthorizationID().equals("dn:"));


    // Authenticate as an additional bind user, and verify that the change is
    // reflected in the extended result.
    conn.bind("cn=Directory Manager", "password");

    result = (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNotNull(result.getAuthorizationID());
    assertTrue(result.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(result.getAuthorizationID().substring(3)),
         new DN("cn=Directory Manager"));


    // Verify that processing fails with a critical control.
    Control[] controls = { new Control("1.2.3.4", true) };
    result = (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest(controls));
    assertEquals(result.getResultCode(),
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);


    // Verify that processing succeeds with only non-critical controls.
    controls = new Control[] { new Control("1.2.3.4", false) };
    result = (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest(controls));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertNotNull(result.getAuthorizationID());
    assertTrue(result.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(result.getAuthorizationID().substring(3)),
         new DN("cn=Directory Manager"));

    conn.close();
  }
}
