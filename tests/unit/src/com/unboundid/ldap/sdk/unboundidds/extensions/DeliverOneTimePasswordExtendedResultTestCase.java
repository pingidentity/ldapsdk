/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
 * This class provides a set of test cases for the
 * {@code DeliverOneTimePasswordExtendedResult} class.
 */
public final class DeliverOneTimePasswordExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a result that indicates that the operation did not
   * complete successfully.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeFailedOperation()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    DeliverOneTimePasswordExtendedResult r =
         new DeliverOneTimePasswordExtendedResult(1,
              ResultCode.UNWILLING_TO_PERFORM, "I don't feel like it",
              "dc=example,dc=com", referralURLs, null, null, null, null);

    r = new DeliverOneTimePasswordExtendedResult(r);
    assertNotNull(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "I don't feel like it");

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNull(r.getOID());

    assertFalse(r.hasValue());
    assertNull(r.getValue());

    assertNull(r.getDeliveryMechanism());

    assertNull(r.getRecipientDN());

    assertNull(r.getRecipientID());

    assertNull(r.getDeliveryMessage());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a success result that does not include a delivery
   * message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResultWithoutMessage()
         throws Exception
  {
    DeliverOneTimePasswordExtendedResult r =
         new DeliverOneTimePasswordExtendedResult(1, ResultCode.SUCCESS, null,
              null, null, "SMS", "uid=auth.user,dc=example,dc=com",
              "123-456-7890", null);

    r = new DeliverOneTimePasswordExtendedResult(r);
    assertNotNull(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.25");

    assertTrue(r.hasValue());
    assertNotNull(r.getValue());

    assertNotNull(r.getDeliveryMechanism());
    assertEquals(r.getDeliveryMechanism(), "SMS");

    assertNotNull(r.getRecipientDN());
    assertDNsEqual(r.getRecipientDN(), "uid=auth.user,dc=example,dc=com");

    assertNotNull(r.getRecipientID());
    assertEquals(r.getRecipientID(), "123-456-7890");

    assertNull(r.getDeliveryMessage());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a success result that includes a delivery message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResultWithMessage()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    DeliverOneTimePasswordExtendedResult r =
         new DeliverOneTimePasswordExtendedResult(1, ResultCode.SUCCESS, null,
              null, null, "SMS", "uid=auth.user,dc=example,dc=com",
              "123-456-7890", "This is the message", controls);

    r = new DeliverOneTimePasswordExtendedResult(r);
    assertNotNull(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.25");

    assertTrue(r.hasValue());
    assertNotNull(r.getValue());

    assertNotNull(r.getDeliveryMechanism());
    assertEquals(r.getDeliveryMechanism(), "SMS");

    assertNotNull(r.getRecipientDN());
    assertDNsEqual(r.getRecipientDN(), "uid=auth.user,dc=example,dc=com");

    assertNotNull(r.getRecipientID());
    assertEquals(r.getRecipientID(), "123-456-7890");

    assertNotNull(r.getDeliveryMessage());
    assertEquals(r.getDeliveryMessage(), "This is the message");

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a success result that includes a delivery message
   * but no delivery mechanism.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testSuccessResultWithMessageButNoMechanism()
         throws Exception
  {
    new DeliverOneTimePasswordExtendedResult(1, ResultCode.SUCCESS, null,
         null, null, null, null, null, "This is the message");
  }



  /**
   * Tests the behavior for a success result that includes a recipient ID but no
   * delivery mechanism.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testSuccessResultWithIDButNoMechanism()
         throws Exception
  {
    new DeliverOneTimePasswordExtendedResult(1, ResultCode.SUCCESS, null,
         null, null, null, null, "uid=test.user@example.com", null);
  }



  /**
   * Tests the behavior for a success result that includes a delivery mechanism
   * but no recipient DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testSuccessResultWithMechanismButNoDN()
         throws Exception
  {
    new DeliverOneTimePasswordExtendedResult(1, ResultCode.SUCCESS, null,
         null, null, null, "uid=auth.user,dc=example,dc=com", null,
         "This is the message");
  }



  /**
   * Tests the behavior when trying to decode an extended result whose value is
   * not an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new DeliverOneTimePasswordExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.25",
         new ASN1OctetString("foo"), null));
  }



  /**
   * Tests the behavior when trying to decode an extended result whose value
   * sequence has an element with an unexpected type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidElement()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "SMS"),
         new ASN1OctetString((byte) 0x81, "uid=test.user,dc=example,dc=com"),
         new ASN1OctetString((byte) 0x82, "test.user@example.com"),
         new ASN1OctetString((byte) 0x83, "Delivery message"),
         new ASN1OctetString((byte) 0x8F, "invalid"));

    new DeliverOneTimePasswordExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.25",
         new ASN1OctetString(valueSequence.encode()), null));
  }



  /**
   * Tests the behavior when trying to decode an extended result whose value
   * sequence is missing the delivery mechanism.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueMissingDeliveryMechanism()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x81, "uid=test.user,dc=example,dc=com"),
         new ASN1OctetString((byte) 0x82, "test.user@example.com"),
         new ASN1OctetString((byte) 0x83, "Delivery message"));

    new DeliverOneTimePasswordExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.25",
         new ASN1OctetString(valueSequence.encode()), null));
  }



  /**
   * Tests the behavior when trying to decode an extended result whose value
   * sequence is missing the recipient DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueMissingRecipientDN()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "SMS"),
         new ASN1OctetString((byte) 0x82, "test.user@example.com"),
         new ASN1OctetString((byte) 0x83, "Delivery message"));

    new DeliverOneTimePasswordExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.25",
         new ASN1OctetString(valueSequence.encode()), null));
  }
}
