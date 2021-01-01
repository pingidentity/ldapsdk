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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * {@code GetSupportedOTPDeliveryMechanismsExtendedResult} class.
 */
public final class GetSupportedOTPDeliveryMechanismsExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a success result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResult()
         throws Exception
  {
    GetSupportedOTPDeliveryMechanismsExtendedResult r =
         new GetSupportedOTPDeliveryMechanismsExtendedResult(1234,
              ResultCode.SUCCESS, null, null, null,
              Arrays.asList(
                   new SupportedOTPDeliveryMechanismInfo("SMS", true,
                        "123-456-7890"),
                   new SupportedOTPDeliveryMechanismInfo("SMS", true,
                        "123-456-7891"),
                   new SupportedOTPDeliveryMechanismInfo("E-Mail", true,
                        "john.doe@example.com"),
                   new SupportedOTPDeliveryMechanismInfo("Mental Telepathy",
                        true, null),
                   new SupportedOTPDeliveryMechanismInfo("Cans and String",
                        false, null),
                   new SupportedOTPDeliveryMechanismInfo("Mystery", null,
                        null)),
              new Control("1.2.3.4"), new Control("5.6.7.8"));

    r = new GetSupportedOTPDeliveryMechanismsExtendedResult(r);

    assertEquals(r.getMessageID(), 1234);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.48");

    assertNotNull(r.getValue());

    assertNotNull(r.getDeliveryMechanismInfo());
    assertEquals(r.getDeliveryMechanismInfo(),
         Arrays.asList(
              new SupportedOTPDeliveryMechanismInfo("SMS", true,
                   "123-456-7890"),
              new SupportedOTPDeliveryMechanismInfo("SMS", true,
                   "123-456-7891"),
              new SupportedOTPDeliveryMechanismInfo("E-Mail", true,
                   "john.doe@example.com"),
              new SupportedOTPDeliveryMechanismInfo("Mental Telepathy", true,
                   null),
              new SupportedOTPDeliveryMechanismInfo("Cans and String", false,
                   null),
              new SupportedOTPDeliveryMechanismInfo("Mystery", null, null)));

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a success result in which the server does not have
   * any delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResultNoMechanisms()
         throws Exception
  {
    GetSupportedOTPDeliveryMechanismsExtendedResult r =
         new GetSupportedOTPDeliveryMechanismsExtendedResult(1234,
              ResultCode.SUCCESS, null, null, null,
              null);

    r = new GetSupportedOTPDeliveryMechanismsExtendedResult(r);

    assertEquals(r.getMessageID(), 1234);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.48");

    assertNotNull(r.getValue());

    assertNotNull(r.getDeliveryMechanismInfo());
    assertTrue(r.getDeliveryMechanismInfo().isEmpty());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a failure result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureResult()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com/",
      "ldap://ds2.example.com/"
    };

    GetSupportedOTPDeliveryMechanismsExtendedResult r =
         new GetSupportedOTPDeliveryMechanismsExtendedResult(5678,
              ResultCode.NO_SUCH_OBJECT, "Unknown user",
              "ou=People,dc=example,dc=com", referralURLs, null);

    r = new GetSupportedOTPDeliveryMechanismsExtendedResult(r);

    assertEquals(r.getMessageID(), 5678);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "Unknown user");

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(), "ou=People,dc=example,dc=com");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNotNull(r.getDeliveryMechanismInfo());
    assertTrue(r.getDeliveryMechanismInfo().isEmpty());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended result whose
   * value is not an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new GetSupportedOTPDeliveryMechanismsExtendedResult(new ExtendedResult(
         1234, ResultCode.SUCCESS, null, null, null,
         "1.3.6.1.4.1.30221.2.6.48", new ASN1OctetString("not a sequence"),
         null));
  }



  /**
   * Tests the behavior when trying to decode an extended result whose
   * value contains a malformed delivery mechanism info object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedDeliveryMechanismInfo()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1OctetString((byte) 0x80, "foo"),
              new ASN1OctetString((byte) 0x12, "bar"),
              new ASN1OctetString((byte) 0x56, "baz")));

    new GetSupportedOTPDeliveryMechanismsExtendedResult(new ExtendedResult(
         1234, ResultCode.SUCCESS, null, null, null,
         "1.3.6.1.4.1.30221.2.6.48",
         new ASN1OctetString(valueSequence.encode()),
         null));
  }
}
