/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the get password quality
 * requirements extended request.
 */
public final class GetPasswordQualityRequirementsExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the extended request to get the password quality
   * requirements for an add operation using the default password policy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddWithDefaultPolicy()
         throws Exception
  {
    GetPasswordQualityRequirementsExtendedRequest r =
         GetPasswordQualityRequirementsExtendedRequest.
              createAddWithDefaultPasswordPolicyRequest(
                   new Control("1.2.3.4"),
                   new Control("5.6.7.8", true));

    r = new GetPasswordQualityRequirementsExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.43");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getTargetType());
    assertEquals(r.getTargetType(),
         GetPasswordQualityRequirementsTargetType.
              ADD_WITH_DEFAULT_PASSWORD_POLICY);

    assertNull(r.getTargetDN());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the extended request to get the password quality
   * requirements for an add operation using a specified password policy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddWithSpecifiedPolicy()
         throws Exception
  {
    GetPasswordQualityRequirementsExtendedRequest r =
         GetPasswordQualityRequirementsExtendedRequest.
              createAddWithSpecifiedPasswordPolicyRequest(
                   "cn=Test,cn=Password Policies,cn=config");

    r = new GetPasswordQualityRequirementsExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.43");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getTargetType());
    assertEquals(r.getTargetType(),
         GetPasswordQualityRequirementsTargetType.
              ADD_WITH_SPECIFIED_PASSWORD_POLICY);

    assertNotNull(r.getTargetDN());
    assertDNsEqual(r.getTargetDN(),
         "cn=Test,cn=Password Policies,cn=config");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the extended request to get the password quality
   * requirements for a self change using the authorization identity of the
   * currently-authenticated user.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSelfChangeAsCurrentUser()
         throws Exception
  {
    GetPasswordQualityRequirementsExtendedRequest r =
         GetPasswordQualityRequirementsExtendedRequest.
              createSelfChangeWithSameAuthorizationIdentityRequest();

    r = new GetPasswordQualityRequirementsExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.43");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getTargetType());
    assertEquals(r.getTargetType(),
         GetPasswordQualityRequirementsTargetType.
              SELF_CHANGE_FOR_AUTHORIZATION_IDENTITY);

    assertNull(r.getTargetDN());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the extended request to get the password quality
   * requirements for a self change for a specified user.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSelfChangeForSpecifiedUser()
         throws Exception
  {
    GetPasswordQualityRequirementsExtendedRequest r =
         GetPasswordQualityRequirementsExtendedRequest.
              createSelfChangeForSpecifiedUserRequest(
                   "uid=test,ou=People,dc=example,dc=com");

    r = new GetPasswordQualityRequirementsExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.43");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getTargetType());
    assertEquals(r.getTargetType(),
         GetPasswordQualityRequirementsTargetType.
              SELF_CHANGE_FOR_SPECIFIED_USER);

    assertNotNull(r.getTargetDN());
    assertDNsEqual(r.getTargetDN(),
         "uid=test,ou=People,dc=example,dc=com");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the extended request to get the password quality
   * requirements for an administrative reset for a specified user.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAdminResetForSpecifiedUser()
         throws Exception
  {
    GetPasswordQualityRequirementsExtendedRequest r =
         GetPasswordQualityRequirementsExtendedRequest.
              createAdministrativeResetForSpecifiedUserRequest(
                   "uid=test,ou=People,dc=example,dc=com");

    r = new GetPasswordQualityRequirementsExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.43");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getTargetType());
    assertEquals(r.getTargetType(),
         GetPasswordQualityRequirementsTargetType.
              ADMINISTRATIVE_RESET_FOR_SPECIFIED_USER);

    assertNotNull(r.getTargetDN());
    assertDNsEqual(r.getTargetDN(),
         "uid=test,ou=People,dc=example,dc=com");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended request that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestWithoutValue()
         throws Exception
  {
    new GetPasswordQualityRequirementsExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.43"));
  }



  /**
   * Tests the behavior when trying to decode an extended request whose value
   * is not an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestValueNotSequence()
         throws Exception
  {
    new GetPasswordQualityRequirementsExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.43", new ASN1OctetString("not a sequence")));
  }



  /**
   * Tests the behavior when trying to decode an extended request whose value
   * sequence contains an unrecognized target type.
   * is not an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestUnknownTargetType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x12, "unknown"));
    final ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    new GetPasswordQualityRequirementsExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.43", value));
  }


  /**
   * Provides test coverage for the {@code process} code method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcess()
         throws Exception
  {
    final LDAPConnection conn = getTestDS().getConnection();

    final ExtendedResult result = conn.processExtendedOperation(
         GetPasswordQualityRequirementsExtendedRequest.
              createAddWithDefaultPasswordPolicyRequest());
    assertNotNull(result);

    assertTrue(result instanceof GetPasswordQualityRequirementsExtendedResult);

    assertResultCodeNot(result, ResultCode.SUCCESS);

    conn.close();
  }
}
