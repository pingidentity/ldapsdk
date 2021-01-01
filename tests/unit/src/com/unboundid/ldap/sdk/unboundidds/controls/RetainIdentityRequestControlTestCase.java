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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityResponseControl;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;



/**
 * This class provides a set of test cases for the RetainIdentityRequestControl
 * class.
 */
public class RetainIdentityRequestControlTestCase
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
    RetainIdentityRequestControl c = new RetainIdentityRequestControl();
    c = new RetainIdentityRequestControl(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a generic control that contains a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2WithValue()
         throws Exception
  {
    Control c = new Control(
         RetainIdentityRequestControl.RETAIN_IDENTITY_REQUEST_OID,
         true, new ASN1OctetString("foo"));
    new RetainIdentityRequestControl(c);
  }



  /**
   * Sends a request to the server containing the retain identity request
   * control.  It will establish an authenticated connection, then send an
   * anonymous simple bind including the retain identity request control  It
   * will verify that the identity of the client connection has not changed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendAnoonymousSimpleRequest()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    // First, use the "Who Am I?" request to get the current authorization
    // identity.
    WhoAmIExtendedResult whoAmIResult =
         (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    String authzID = whoAmIResult.getAuthorizationID();
    assertNotNull(authzID);


    // Perform an anonymous simple bind that includes both the retain identity
    // request control and the authorization identity request control.
    Control[] controls =
    {
      new RetainIdentityRequestControl(),
      new AuthorizationIdentityRequestControl()
    };
    SimpleBindRequest bindRequest = new SimpleBindRequest("", "", controls);

    BindResult bindResult = conn.bind(bindRequest);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    boolean authzIDFound = false;
    for (Control c : bindResult.getResponseControls())
    {
      if (c instanceof AuthorizationIdentityResponseControl)
      {
        authzIDFound = true;
        String bindAuthzID =
             ((AuthorizationIdentityResponseControl) c).getAuthorizationID();
        assertNotNull(bindAuthzID);
        assertTrue(bindAuthzID.equals("") || bindAuthzID.equals("dn:"));
        assertFalse(bindAuthzID.equals(authzID));
        break;
      }
    }

    assertTrue(authzIDFound);


    // Use the "Who Am I?" request again to verify that the client identity
    // hasn't really changed.
    whoAmIResult = (WhoAmIExtendedResult)
                   conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertNotNull(whoAmIResult.getAuthorizationID());
    assertEquals(whoAmIResult.getAuthorizationID(), authzID);

    conn.close();
  }



  /**
   * Sends a request to the server containing the retain identity request
   * control.  It will establish an unauthenticated connection, then send an
   * authenticated simple bind including the retain identity request control  It
   * will verify that the identity of the client connection has not changed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendAuthenticatedSimpleRequest()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.add("dn: uid=test," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "uid: test",
             "userPassword: password");


    // First, use the "Who Am I?" request to get the current authorization
    // identity.
    WhoAmIExtendedResult whoAmIResult =
         (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    String authzID = whoAmIResult.getAuthorizationID();
    assertNotNull(authzID);


    // Perform an authenticated simple bind that includes both the retain
    // identity request control and the authorization identity request control.
    Control[] controls =
    {
      new RetainIdentityRequestControl(),
      new AuthorizationIdentityRequestControl()
    };
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("uid=test," + getTestBaseDN(), "password",
                               controls);

    BindResult bindResult = conn.bind(bindRequest);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    boolean authzIDFound = false;
    for (Control c : bindResult.getResponseControls())
    {
      if (c instanceof AuthorizationIdentityResponseControl)
      {
        authzIDFound = true;
        String bindAuthzID =
             ((AuthorizationIdentityResponseControl) c).getAuthorizationID();
        assertNotNull(bindAuthzID);
        assertFalse(bindAuthzID.equals(authzID));
        break;
      }
    }

    assertTrue(authzIDFound);


    // Use the "Who Am I?" request again to verify that the client identity
    // hasn't really changed.
    whoAmIResult = (WhoAmIExtendedResult)
                   conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertNotNull(whoAmIResult.getAuthorizationID());
    assertEquals(whoAmIResult.getAuthorizationID(), authzID);

    conn.delete("uid=test," + getTestBaseDN());
    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Sends a request to the server containing the retain identity request
   * control.  It will establish an unauthenticated connection, then send an
   * authenticated simple bind with invalid credentials including the retain
   * identity request control  It will verify that the identity of the client
   * connection has not changed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendFailedSimpleRequest()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.add("dn: uid=test," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "uid: test",
             "userPassword: password");


    // First, use the "Who Am I?" request to get the current authorization
    // identity.
    WhoAmIExtendedResult whoAmIResult =
         (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    String authzID = whoAmIResult.getAuthorizationID();
    assertNotNull(authzID);


    // Perform an authenticated simple bind that includes both the retain
    // identity request control and the authorization identity request control.
    Control[] controls =
    {
      new RetainIdentityRequestControl(),
    };
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("uid=test," + getTestBaseDN(), "wrong",
                               controls);

    try
    {
      BindResult bindResult = conn.bind(bindRequest);
      assertEquals(bindResult.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }


    // Use the "Who Am I?" request again to verify that the client identity
    // hasn't really changed.
    whoAmIResult = (WhoAmIExtendedResult)
                   conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertNotNull(whoAmIResult.getAuthorizationID());
    assertEquals(whoAmIResult.getAuthorizationID(), authzID);

    conn.delete("uid=test," + getTestBaseDN());
    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Sends a request to the server containing the retain identity request
   * control.  It will establish an unauthenticated connection, then send a SASL
   * PLAIN bind including the retain identity request control  It will verify
   * that the identity of the client connection has not changed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendAuthenticatedPLAINRequest()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.add("dn: uid=test," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "uid: test",
             "userPassword: password");


    // First, use the "Who Am I?" request to get the current authorization
    // identity.
    WhoAmIExtendedResult whoAmIResult =
         (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    String authzID = whoAmIResult.getAuthorizationID();
    assertNotNull(authzID);


    // Perform an authenticated simple bind that includes both the retain
    // identity request control and the authorization identity request control.
    Control[] controls =
    {
      new RetainIdentityRequestControl(),
      new AuthorizationIdentityRequestControl()
    };
    PLAINBindRequest bindRequest =
         new PLAINBindRequest("dn:uid=test," + getTestBaseDN(), "password",
                              controls);

    BindResult bindResult = conn.bind(bindRequest);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    boolean authzIDFound = false;
    for (Control c : bindResult.getResponseControls())
    {
      if (c instanceof AuthorizationIdentityResponseControl)
      {
        authzIDFound = true;
        String bindAuthzID =
             ((AuthorizationIdentityResponseControl) c).getAuthorizationID();
        assertNotNull(bindAuthzID);
        assertFalse(bindAuthzID.equals(authzID));
        break;
      }
    }

    assertTrue(authzIDFound);


    // Use the "Who Am I?" request again to verify that the client identity
    // hasn't really changed.
    whoAmIResult = (WhoAmIExtendedResult)
                   conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertNotNull(whoAmIResult.getAuthorizationID());
    assertEquals(whoAmIResult.getAuthorizationID(), authzID);

    conn.delete("uid=test," + getTestBaseDN());
    conn.delete(getTestBaseDN());
    conn.close();
  }
}
