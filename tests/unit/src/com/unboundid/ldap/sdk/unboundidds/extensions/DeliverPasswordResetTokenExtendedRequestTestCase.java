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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ObjectPair;



/**
 * This class provides test coverage for the deliver password reset token
 * extended request.
 */
public final class DeliverPasswordResetTokenExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor that takes a user DN and varargs preferred delivery
   * mechanisms without providing any delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoPreferredDeliveryMechanisms()
         throws Exception
  {
    DeliverPasswordResetTokenExtendedRequest r =
         new DeliverPasswordResetTokenExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com");

    r = new DeliverPasswordResetTokenExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.45");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeToken());

    assertNull(r.getFullTextAfterToken());

    assertNull(r.getCompactTextBeforeToken());

    assertNull(r.getCompactTextAfterToken());

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertTrue(r.getPreferredDeliveryMechanisms().isEmpty());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the constructor that takes a user DN and varargs preferred delivery
   * mechanisms with a {@code null} value for the set of delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullPreferredDeliveryMechanisms()
         throws Exception
  {
    DeliverPasswordResetTokenExtendedRequest r =
         new DeliverPasswordResetTokenExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com",
              (String[]) null);

    r = new DeliverPasswordResetTokenExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.45");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeToken());

    assertNull(r.getFullTextAfterToken());

    assertNull(r.getCompactTextBeforeToken());

    assertNull(r.getCompactTextAfterToken());

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertTrue(r.getPreferredDeliveryMechanisms().isEmpty());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the constructor that takes a user DN and varargs preferred delivery
   * mechanisms with a non-empty set of delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithPreferredDeliveryMechanisms()
         throws Exception
  {
    DeliverPasswordResetTokenExtendedRequest r =
         new DeliverPasswordResetTokenExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com", "SMS", "Email");

    r = new DeliverPasswordResetTokenExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.45");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeToken());

    assertNull(r.getFullTextAfterToken());

    assertNull(r.getCompactTextBeforeToken());

    assertNull(r.getCompactTextAfterToken());

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms().size(), 2);
    assertEquals(r.getPreferredDeliveryMechanisms().get(0).getFirst(), "SMS");
    assertNull(r.getPreferredDeliveryMechanisms().get(0).getSecond());
    assertEquals(r.getPreferredDeliveryMechanisms().get(1).getFirst(), "Email");
    assertNull(r.getPreferredDeliveryMechanisms().get(1).getSecond());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the constructor that takes a user DN and varargs preferred delivery
   * mechanisms with a non-empty set of delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithPreferredDeliveryMechanismsWithRecipientIDs()
         throws Exception
  {
    final ArrayList<ObjectPair<String,String>> pdmList =
         new ArrayList<ObjectPair<String,String>>(2);
    pdmList.add(new ObjectPair<String,String>("SMS", "123-456-7890"));
    pdmList.add(new ObjectPair<String,String>("Email", "tuser@example.com"));

    DeliverPasswordResetTokenExtendedRequest r =
         new DeliverPasswordResetTokenExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com", pdmList,
              new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new DeliverPasswordResetTokenExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.45");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeToken());

    assertNull(r.getFullTextAfterToken());

    assertNull(r.getCompactTextBeforeToken());

    assertNull(r.getCompactTextAfterToken());

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms().size(), 2);
    assertEquals(r.getPreferredDeliveryMechanisms().get(0).getFirst(), "SMS");
    assertEquals(r.getPreferredDeliveryMechanisms().get(0).getSecond(),
         "123-456-7890");
    assertEquals(r.getPreferredDeliveryMechanisms().get(1).getFirst(), "Email");
    assertEquals(r.getPreferredDeliveryMechanisms().get(1).getSecond(),
         "tuser@example.com");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the constructor that takes a user DN and varargs preferred delivery
   * mechanisms with a non-empty set of delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithMessageComponents()
         throws Exception
  {
    final ArrayList<ObjectPair<String,String>> pdmList =
         new ArrayList<ObjectPair<String,String>>(2);
    pdmList.add(new ObjectPair<String,String>("SMS", "123-456-7890"));
    pdmList.add(new ObjectPair<String,String>("Email", "tuser@example.com"));

    DeliverPasswordResetTokenExtendedRequest r =
         new DeliverPasswordResetTokenExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com",
              "Message Subject", "Full Before", "Full After",
              "Compact Before", "Compact After", pdmList,
              new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new DeliverPasswordResetTokenExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.45");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getMessageSubject());
    assertEquals(r.getMessageSubject(), "Message Subject");

    assertNotNull(r.getFullTextBeforeToken());
    assertEquals(r.getFullTextBeforeToken(), "Full Before");

    assertNotNull(r.getFullTextAfterToken());
    assertEquals(r.getFullTextAfterToken(), "Full After");

    assertNotNull(r.getCompactTextBeforeToken());
    assertEquals(r.getCompactTextBeforeToken(), "Compact Before");

    assertNotNull(r.getCompactTextAfterToken());
    assertEquals(r.getCompactTextAfterToken(), "Compact After");

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms().size(), 2);
    assertEquals(r.getPreferredDeliveryMechanisms().get(0).getFirst(), "SMS");
    assertEquals(r.getPreferredDeliveryMechanisms().get(0).getSecond(),
         "123-456-7890");
    assertEquals(r.getPreferredDeliveryMechanisms().get(1).getFirst(), "Email");
    assertEquals(r.getPreferredDeliveryMechanisms().get(1).getSecond(),
         "tuser@example.com");

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
    new DeliverPasswordResetTokenExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.45"));
  }



  /**
   * Tests the behavior when trying to decode a request with a value that cannot
   * be decoded as a valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new DeliverPasswordResetTokenExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.45", new ASN1OctetString("invalid")));
  }



  /**
   * Tests the behavior when trying to decode a request with a value whose
   * sequence contains an element with an unrecognized BER type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueUnrecognizedSequenceElement()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("uid=test.user,ou=People,dc=example,dc=com"),
         new ASN1OctetString((byte) 0x12, "foo"));

    new DeliverPasswordResetTokenExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.45",
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when sending the request to a directory server.  The
   * request will not be successful because the in-memory directory server
   * does not support this operation, but it will at least provide test
   * coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequest()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();
    final LDAPConnection conn = ds.getConnection();

    final ExtendedResult result = conn.processExtendedOperation(
         new DeliverPasswordResetTokenExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(result);
    assertResultCodeNot(result, ResultCode.SUCCESS);
    assertTrue(result instanceof DeliverPasswordResetTokenExtendedResult);

    conn.close();
  }
}
