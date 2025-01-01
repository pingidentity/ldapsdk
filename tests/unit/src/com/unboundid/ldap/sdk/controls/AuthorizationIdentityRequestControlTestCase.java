/*
 * Copyright 2007-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2025 Ping Identity Corporation
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
 * Copyright (C) 2007-2025 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the
 * AuthorizationIdentityRequestControl class.
 */
public class AuthorizationIdentityRequestControlTestCase
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
    AuthorizationIdentityRequestControl c =
         new AuthorizationIdentityRequestControl();
    c = new AuthorizationIdentityRequestControl(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
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
    AuthorizationIdentityRequestControl c =
         new AuthorizationIdentityRequestControl(true);
    c = new AuthorizationIdentityRequestControl(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a control that contains a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3WithValue()
         throws Exception
  {
    Control c = new Control(AuthorizationIdentityRequestControl.
                                 AUTHORIZATION_IDENTITY_REQUEST_OID,
                            true, new ASN1OctetString("foo"));
    new AuthorizationIdentityRequestControl(c);
  }



  /**
   * Sends an anonymous simple bind request to the server that includes the
   * authorization identity request control and in which the response should
   * include the authorization identity response control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendAnonymousBindRequestWithControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    Control[] controls =
    {
      new AuthorizationIdentityRequestControl()
    };

    SimpleBindRequest bindRequest = new SimpleBindRequest("", "", controls);
    BindResult bindResult = conn.bind(bindRequest);

    boolean hasControl = false;
    for (Control c : bindResult.getResponseControls())
    {
      if (c instanceof AuthorizationIdentityResponseControl)
      {
        hasControl = true;
        AuthorizationIdentityResponseControl airc =
             (AuthorizationIdentityResponseControl) c;
        assertTrue(airc.getAuthorizationID().equals("") ||
                   airc.getAuthorizationID().equals("dn:"));
      }
      else if (c.getOID().equals(AuthorizationIdentityResponseControl.
                                      AUTHORIZATION_IDENTITY_RESPONSE_OID))
      {
        fail("Failed to decode a response control with the appropriate " +
             "OID as an authorization identity response.");
      }
    }

    conn.close();
    assertTrue(hasControl);
  }



  /**
   * Sends a non-anonymous simple bind request to the server that includes the
   * authorization identity request control and in which the response should
   * include the authorization identity response control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendAdminBindRequestWithControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    Control[] controls =
    {
      new AuthorizationIdentityRequestControl()
    };

    SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), getTestBindPassword(),
                               controls);
    BindResult bindResult = conn.bind(bindRequest);

    boolean hasControl = false;
    for (Control c : bindResult.getResponseControls())
    {
      if (c instanceof AuthorizationIdentityResponseControl)
      {
        hasControl = true;
        AuthorizationIdentityResponseControl airc =
             (AuthorizationIdentityResponseControl) c;
        assertTrue(airc.getAuthorizationID().length() > 0);
      }
      else if (c.getOID().equals(AuthorizationIdentityResponseControl.
                                      AUTHORIZATION_IDENTITY_RESPONSE_OID))
      {
        fail("Failed to decode a response control with the appropriate " +
             "OID as an authorization identity response.");
      }
    }

    conn.close();
    assertTrue(hasControl);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControl()
          throws Exception
  {
    final AuthorizationIdentityRequestControl c =
         new AuthorizationIdentityRequestControl(false);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 3);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    assertFalse(controlObject.hasField("value-json"));


    AuthorizationIdentityRequestControl decodedControl =
         AuthorizationIdentityRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getValue());


    decodedControl =
         (AuthorizationIdentityRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getValue());
  }
}
