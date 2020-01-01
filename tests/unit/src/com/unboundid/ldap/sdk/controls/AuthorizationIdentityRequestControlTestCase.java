/*
 * Copyright 2007-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2020 Ping Identity Corporation
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
}
