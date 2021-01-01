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
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * {@code GetSupportedOTPDeliveryMechanismsExtendedRequest} class.
 */
public final class GetSupportedOTPDeliveryMechanismsExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the request without controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutControls()
         throws Exception
  {
    GetSupportedOTPDeliveryMechanismsExtendedRequest r =
         new GetSupportedOTPDeliveryMechanismsExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com");

    r = new GetSupportedOTPDeliveryMechanismsExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.47");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the request with controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithControls()
         throws Exception
  {
    GetSupportedOTPDeliveryMechanismsExtendedRequest r =
         new GetSupportedOTPDeliveryMechanismsExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com",
              new Control("1.2.3.4"), new Control("5.6.7.8"));

    r = new GetSupportedOTPDeliveryMechanismsExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.47");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode a generic extended request that
   * does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new GetSupportedOTPDeliveryMechanismsExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.47"));
  }



  /**
   * Tests the behavior when trying to decode a generic extended request whose
   * value is not a valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new GetSupportedOTPDeliveryMechanismsExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.47",
              new ASN1OctetString("this is not a valid ASN.1 sequence")));
  }


  /**
   * Provides test coverage for the {@code process} code method.  This will
   * fail, since the in-memory directory server doesn't support this operation,
   * but it will at least get coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcess()
         throws Exception
  {
    final LDAPConnection conn = getTestDS().getConnection();

    final ExtendedResult result = conn.processExtendedOperation(
         new GetSupportedOTPDeliveryMechanismsExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(result);

    assertTrue(result instanceof
         GetSupportedOTPDeliveryMechanismsExtendedResult);

    assertResultCodeNot(result, ResultCode.SUCCESS);

    conn.close();
  }
}
