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



import java.util.ArrayList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Long;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ObjectPair;



/**
 * This class provides a set of test cases for the
 * {@code DeliverSingleUseTokenExtendedRequest} class.
 */
public final class DeliverSingleUseTokenExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a case in which the token should only be delivered to a usable
   * account.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyUsableAccount()
         throws Exception
  {
    DeliverSingleUseTokenExtendedRequest r =
         new DeliverSingleUseTokenExtendedRequest(
              "uid=test.user,dc=example,dc=com", "testOnlyUsableAccount",
              300000L, "subject", "fullBefore", "fullAfter", "compactBefore",
              "compactAfter", null, false, false, false, false);

    r = new DeliverSingleUseTokenExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.49");

    assertNotNull(r.getValue());

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,dc=example,dc=com");

    assertNotNull(r.getTokenID());
    assertEquals(r.getTokenID(), "testOnlyUsableAccount");

    assertNotNull(r.getValidityDurationMillis());
    assertEquals(r.getValidityDurationMillis().longValue(), 300000L);

    assertNotNull(r.getMessageSubject());
    assertEquals(r.getMessageSubject(), "subject");

    assertNotNull(r.getFullTextBeforeToken());
    assertEquals(r.getFullTextBeforeToken(), "fullBefore");

    assertNotNull(r.getFullTextAfterToken());
    assertEquals(r.getFullTextAfterToken(), "fullAfter");

    assertNotNull(r.getCompactTextBeforeToken());
    assertEquals(r.getCompactTextBeforeToken(), "compactBefore");

    assertNotNull(r.getCompactTextAfterToken());
    assertEquals(r.getCompactTextAfterToken(), "compactAfter");

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertTrue(r.getPreferredDeliveryMechanisms().isEmpty());

    assertFalse(r.deliverIfPasswordExpired());

    assertFalse(r.deliverIfAccountLocked());

    assertFalse(r.deliverIfAccountDisabled());

    assertFalse(r.deliverIfAccountExpired());

    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests a case in which the token should only be delivered to an account that
   * would be usable after an administrator resets the user's password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSomewhatUsableAccount()
         throws Exception
  {
    final ArrayList<ObjectPair<String,String>> preferredDeliveryMechanisms =
         new ArrayList<ObjectPair<String,String>>(3);
    preferredDeliveryMechanisms.add(
         new ObjectPair<String,String>("Email", "tuser@example.com"));
    preferredDeliveryMechanisms.add(
         new ObjectPair<String, String>("SMS", "123-456-7890"));
    preferredDeliveryMechanisms.add(
         new ObjectPair<String,String>("Mental Telepathy", null));

    DeliverSingleUseTokenExtendedRequest r =
         new DeliverSingleUseTokenExtendedRequest(
              "uid=test.user,dc=example,dc=com", "testSomewhatUsableAccount",
              1234567L, null, "fullBefore", "fullAfter", "compactBefore",
              "compactAfter", preferredDeliveryMechanisms, true, true, false,
              false, new Control("1.2.3.4"), new Control("4.5.6.7"));

    r = new DeliverSingleUseTokenExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.49");

    assertNotNull(r.getValue());

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,dc=example,dc=com");

    assertNotNull(r.getTokenID());
    assertEquals(r.getTokenID(), "testSomewhatUsableAccount");

    assertNotNull(r.getValidityDurationMillis());
    assertEquals(r.getValidityDurationMillis().longValue(), 1234567L);

    assertNull(r.getMessageSubject());

    assertNotNull(r.getFullTextBeforeToken());
    assertEquals(r.getFullTextBeforeToken(), "fullBefore");

    assertNotNull(r.getFullTextAfterToken());
    assertEquals(r.getFullTextAfterToken(), "fullAfter");

    assertNotNull(r.getCompactTextBeforeToken());
    assertEquals(r.getCompactTextBeforeToken(), "compactBefore");

    assertNotNull(r.getCompactTextAfterToken());
    assertEquals(r.getCompactTextAfterToken(), "compactAfter");

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms(),
         preferredDeliveryMechanisms);

    assertTrue(r.deliverIfPasswordExpired());

    assertTrue(r.deliverIfAccountLocked());

    assertFalse(r.deliverIfAccountDisabled());

    assertFalse(r.deliverIfAccountExpired());

    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests a case in which the token should be delivered no matter what.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAnythingGoes()
         throws Exception
  {
    final ArrayList<ObjectPair<String,String>> preferredDeliveryMechanisms =
         new ArrayList<ObjectPair<String,String>>(1);
    preferredDeliveryMechanisms.add(
         new ObjectPair<String,String>("Email", "tuser@example.com"));

    DeliverSingleUseTokenExtendedRequest r =
         new DeliverSingleUseTokenExtendedRequest(
              "uid=test.user,dc=example,dc=com", "testAnythingGoes",
              null, null, null, null, null, null, preferredDeliveryMechanisms,
              true, true, true, true);

    r = new DeliverSingleUseTokenExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.49");

    assertNotNull(r.getValue());

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,dc=example,dc=com");

    assertNotNull(r.getTokenID());
    assertEquals(r.getTokenID(), "testAnythingGoes");

    assertNull(r.getValidityDurationMillis());

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeToken());

    assertNull(r.getFullTextAfterToken());

    assertNull(r.getCompactTextBeforeToken());

    assertNull(r.getCompactTextAfterToken());

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms(),
         preferredDeliveryMechanisms);

    assertTrue(r.deliverIfPasswordExpired());

    assertTrue(r.deliverIfAccountLocked());

    assertTrue(r.deliverIfAccountDisabled());

    assertTrue(r.deliverIfAccountExpired());

    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode a request that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new DeliverSingleUseTokenExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.49", (ASN1OctetString) null));
  }



  /**
   * Tests the behavior when trying to decode a request that has a value that
   * cannot be decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new DeliverSingleUseTokenExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.49", new ASN1OctetString("not a sequence")));
  }



  /**
   * Tests the behavior when trying to decode a request that has a value
   * sequence with an element that has an unknown type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceUnknownElement()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("uid=test.user,dc=example,dc=com"),
         new ASN1OctetString("tokenID"),
         new ASN1Long(123456L),
         new ASN1OctetString((byte) 0x12, "What's this?"));

    new DeliverSingleUseTokenExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.49",
         new ASN1OctetString(valueSequence.encode())));
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
         new DeliverSingleUseTokenExtendedRequest(
              "uid=test.user,dc=example,dc=com", "tokenID", 1234567L, null,
              null, null, null, null, null, false, false, false, false));
    assertNotNull(result);

    assertTrue(result instanceof DeliverSingleUseTokenExtendedResult);

    assertResultCodeNot(result, ResultCode.SUCCESS);

    conn.close();
  }
}
