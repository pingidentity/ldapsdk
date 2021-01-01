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
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the generate TOTP shared secret
 * extended result.
 */
public final class GenerateTOTPSharedSecretExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the result for the case in which the server was able
   * to successfully generate a TOTP shared secret.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResult()
         throws Exception
  {
    GenerateTOTPSharedSecretExtendedResult r =
         new GenerateTOTPSharedSecretExtendedResult(1, "abcdefghijklmnop",
              new Control("1.2.3.4"), new Control("5.6.7.8"));

    r = new GenerateTOTPSharedSecretExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getTOTPSharedSecret());
    assertEquals(r.getTOTPSharedSecret(), "abcdefghijklmnop");

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.57");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the result for the case in which the server was able
   * to successfully generate a TOTP shared secret but the secret was not
   * included in the result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testSuccessResultNullSecret()
         throws Exception
  {
    new GenerateTOTPSharedSecretExtendedResult(1, null);
  }



  /**
   * Tests the behavior of the result for the case in which the server rejected
   * the request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureResult()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    GenerateTOTPSharedSecretExtendedResult r =
         new GenerateTOTPSharedSecretExtendedResult(2,
              ResultCode.UNWILLING_TO_PERFORM, "I don't feel like it",
              "dc=example,dc=com", referralURLs, null);

    r = new GenerateTOTPSharedSecretExtendedResult(r);

    assertEquals(r.getMessageID(), 2);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "I don't feel like it");

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNull(r.getTOTPSharedSecret());

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the extended result when trying to decode a generic
   * result that has a value that is not an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeResultValueNotSequence()
         throws Exception
  {
    final ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null,
         null, null, "1.3.6.1.4.1.30221.2.6.57",
         new ASN1OctetString("malformed"), null);
    new GenerateTOTPSharedSecretExtendedResult(r);
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
    final ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null,
         null, null, "1.3.6.1.4.1.30221.2.6.57",
         new ASN1OctetString(new ASN1Sequence().encode()), null);
    new GenerateTOTPSharedSecretExtendedResult(r);
  }
}
