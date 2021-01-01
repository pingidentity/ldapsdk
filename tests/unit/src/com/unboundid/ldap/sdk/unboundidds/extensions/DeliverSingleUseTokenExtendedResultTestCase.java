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
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides test coverage for the deliver single-use token extended
 * result.
 */
public final class DeliverSingleUseTokenExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a success result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResult()
         throws Exception
  {
    DeliverSingleUseTokenExtendedResult r =
         new DeliverSingleUseTokenExtendedResult(1, ResultCode.SUCCESS,
              null, null, null, "SMS", "123-456-7890",
              "Sent a password reset token via SMS to 123-456-7890");

    r = new DeliverSingleUseTokenExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.50");

    assertNotNull(r.getValue());

    assertNotNull(r.getDeliveryMechanism());
    assertEquals(r.getDeliveryMechanism(), "SMS");

    assertNotNull(r.getRecipientID());
    assertEquals(r.getRecipientID(), "123-456-7890");

    assertNotNull(r.getDeliveryMessage());
    assertEquals(r.getDeliveryMessage(),
         "Sent a password reset token via SMS to 123-456-7890");

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a failure result.
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

    DeliverSingleUseTokenExtendedResult r =
         new DeliverSingleUseTokenExtendedResult(2,
              ResultCode.NO_SUCH_OBJECT, "The user does not exist",
              "ou=People,dc=example,dc=com", referralURLs, null, null, null,
              new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new DeliverSingleUseTokenExtendedResult(r);

    assertEquals(r.getMessageID(), 2);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "The user does not exist");

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(), "ou=People,dc=example,dc=com");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNull(r.getDeliveryMechanism());

    assertNull(r.getRecipientID());

    assertNull(r.getDeliveryMessage());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a failure result that does not have a
   * delivery mechanism but does have a recipient ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testFailureResultWithNonNullRecipientID()
         throws Exception
  {
    new DeliverSingleUseTokenExtendedResult(2,
         ResultCode.NO_SUCH_OBJECT, "The user does not exist",
         "ou=People,dc=example,dc=com", null, null, "recipient ID", null);
  }



  /**
   * Provides test coverage for a failure result that does not have a
   * delivery mechanism but does have a delivery message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testFailureResultWithNonNullDeliveryMessage()
         throws Exception
  {
    new DeliverSingleUseTokenExtendedResult(2,
         ResultCode.NO_SUCH_OBJECT, "The user does not exist",
         "ou=People,dc=example,dc=com", null, null, null, "delivery message");
  }



  /**
   * Tests the behavior when trying to decode a result with a value that cannot
   * be decoded as a valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new DeliverSingleUseTokenExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.50",
         new ASN1OctetString("invalid"), null));
  }



  /**
   * Tests the behavior when trying to decode a result with a value whose
   * sequence contains an element with an unrecognized BER type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueUnrecognizedSequenceElement()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("Email"),
         new ASN1OctetString((byte) 0x80, "test.user@example.com"),
         new ASN1OctetString((byte) 0x12, "invalid"));

    new DeliverSingleUseTokenExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.50",
         new ASN1OctetString(valueSequence.encode()), null));
  }
}
