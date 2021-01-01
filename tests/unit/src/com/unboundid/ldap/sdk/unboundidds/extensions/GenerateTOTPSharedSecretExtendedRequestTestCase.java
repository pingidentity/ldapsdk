/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the generate TOTP shared secret
 * extended request.
 */
public final class GenerateTOTPSharedSecretExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the extended request with both an authentication ID
   * and a static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestWithAuthIDWithPassword()
         throws Exception
  {
    GenerateTOTPSharedSecretExtendedRequest r =
         new GenerateTOTPSharedSecretExtendedRequest("u:test.user", "password",
              new Control("1.2.3.4"), new Control("5.6.7.8"));

    r = r.duplicate();
    assertNotNull(r);

    r = new GenerateTOTPSharedSecretExtendedRequest(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getStaticPasswordString());
    assertEquals(r.getStaticPasswordString(), "password");

    assertNotNull(r.getStaticPasswordBytes());
    assertEquals(r.getStaticPasswordBytes(), "password".getBytes("UTF-8"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.56");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the extended request with an authentication ID but
   * no password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestWithAuthIDNoPassword()
         throws Exception
  {
    GenerateTOTPSharedSecretExtendedRequest r =
         new GenerateTOTPSharedSecretExtendedRequest("u:test.user",
              (String) null);

    r = r.duplicate();
    assertNotNull(r);

    r = new GenerateTOTPSharedSecretExtendedRequest(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNull(r.getStaticPasswordString());

    assertNull(r.getStaticPasswordBytes());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.56");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the extended request with an static password but no
   * authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestNoAuthIDWithPassword()
         throws Exception
  {
    GenerateTOTPSharedSecretExtendedRequest r =
         new GenerateTOTPSharedSecretExtendedRequest(null,
              "password".getBytes("UTF-8"));

    r = r.duplicate();
    assertNotNull(r);

    r = new GenerateTOTPSharedSecretExtendedRequest(r);

    assertNull(r.getAuthenticationID());

    assertNotNull(r.getStaticPasswordString());
    assertEquals(r.getStaticPasswordString(), "password");

    assertNotNull(r.getStaticPasswordBytes());
    assertEquals(r.getStaticPasswordBytes(), "password".getBytes("UTF-8"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.56");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the extended request with neither an authentication
   * ID nor a static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testRequestNoAuthIDNoPassword()
         throws Exception
  {
    new GenerateTOTPSharedSecretExtendedRequest(null, (String) null);
  }



  /**
   * Tests the behavior of the extended request when trying to decode a generic
   * request that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestWithoutValue()
         throws Exception
  {
    final ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.56");
    new GenerateTOTPSharedSecretExtendedRequest(r);
  }



  /**
   * Tests the behavior of the extended request when trying to decode a generic
   * request that has a value that is not an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestValueNotSequence()
         throws Exception
  {
    final ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.56",
         new ASN1OctetString("malformed"));
    new GenerateTOTPSharedSecretExtendedRequest(r);
  }



  /**
   * Tests the behavior of the extended request when trying to decode a generic
   * request that has a value that is an empty ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestValueEmptySequence()
         throws Exception
  {
    final ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.56",
         new ASN1OctetString(new ASN1Sequence().encode()));
    new GenerateTOTPSharedSecretExtendedRequest(r);
  }



  /**
   * Tests the behavior of the extended request when trying to decode a generic
   * request that has a value that is an ASN.1 sequence with an unrecognized
   * element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestValueSequenceUnrecognizedElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "u:test.user"),
         new ASN1OctetString((byte) 0x12, "invalid-type"));

    final ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.56",
         new ASN1OctetString(valueSequence.encode()));
    new GenerateTOTPSharedSecretExtendedRequest(r);
  }



  /**
   * Tests the behavior when trying to process a generate TOTP shared secret
   * request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessRequest()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         TestTOTPSharedSecretExtendedOperationHandler.getDSWithSupport();

    LDAPConnection conn = null;
    try
    {
      conn = ds.getConnection();

      conn.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
      conn.add(
           "dn: ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");
      conn.add(
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "userPassword: password");

      final GenerateTOTPSharedSecretExtendedRequest generateTOTPRequest =
           new GenerateTOTPSharedSecretExtendedRequest("u:test.user",
                "password");

      final GenerateTOTPSharedSecretExtendedResult generateTOTPResult =
           (GenerateTOTPSharedSecretExtendedResult)
           conn.processExtendedOperation(generateTOTPRequest);

      assertResultCodeEquals(generateTOTPResult, ResultCode.SUCCESS);

      assertNotNull(generateTOTPResult.getTOTPSharedSecret());
      assertEquals(generateTOTPResult.getTOTPSharedSecret().length(), 16);
    }
    finally
    {
      if (conn != null)
      {
        conn.close();
      }

      ds.shutDown(true);
    }
  }
}
