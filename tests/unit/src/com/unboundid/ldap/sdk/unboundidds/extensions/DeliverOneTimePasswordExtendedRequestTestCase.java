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



import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

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
import com.unboundid.util.ObjectPair;



/**
 * This class provides a set of test cases for the
 * {@code DeliverOneTimePasswordExtendedRequest} class.
 */
public final class DeliverOneTimePasswordExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the class with a null string password and without a
   * set of preferred delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullStringPasswordWithoutDeliveryMechanisms()
         throws Exception
  {
    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id", (String) null);

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNull(r.getStaticPassword());

    assertNull(r.getPreferredDeliveryMechanisms());

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertTrue(r.getPreferredDeliveryMechanismNamesAndIDs().isEmpty());

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeOTP());

    assertNull(r.getFullTextAfterOTP());

    assertNull(r.getCompactTextBeforeOTP());

    assertNull(r.getCompactTextAfterOTP());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the class with a string password and without a set of
   * preferred delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringPasswordWithoutDeliveryMechanisms()
         throws Exception
  {
    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id", "password");

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNull(r.getPreferredDeliveryMechanisms());

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertTrue(r.getPreferredDeliveryMechanismNamesAndIDs().isEmpty());

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeOTP());

    assertNull(r.getFullTextAfterOTP());

    assertNull(r.getCompactTextBeforeOTP());

    assertNull(r.getCompactTextAfterOTP());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the class with a string password and a set of
   * preferred delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringPasswordWithDeliveryMechanisms()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id", "password",
              Arrays.asList("SMS", "Voice", "E-Mail"), controls);

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms(),
         Arrays.asList("SMS", "Voice", "E-Mail"));

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertEquals(r.getPreferredDeliveryMechanismNamesAndIDs().size(), 3);

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeOTP());

    assertNull(r.getFullTextAfterOTP());

    assertNull(r.getCompactTextBeforeOTP());

    assertNull(r.getCompactTextAfterOTP());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the class with a null byte array password and without
   * a set of preferred delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullBytePasswordWithoutDeliveryMechanisms()
         throws Exception
  {
    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id", (String) null);

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNull(r.getStaticPassword());

    assertNull(r.getPreferredDeliveryMechanisms());

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertTrue(r.getPreferredDeliveryMechanismNamesAndIDs().isEmpty());

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeOTP());

    assertNull(r.getFullTextAfterOTP());

    assertNull(r.getCompactTextBeforeOTP());

    assertNull(r.getCompactTextAfterOTP());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the class with a byte array password and without a
   * set of preferred delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBytePasswordWithoutDeliveryMechanisms()
         throws Exception
  {
    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id",
              "password".getBytes("UTF-8"));

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNull(r.getPreferredDeliveryMechanisms());

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertTrue(r.getPreferredDeliveryMechanismNamesAndIDs().isEmpty());

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeOTP());

    assertNull(r.getFullTextAfterOTP());

    assertNull(r.getCompactTextBeforeOTP());

    assertNull(r.getCompactTextAfterOTP());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the class with a byte array password and a set of
   * preferred delivery mechanisms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBytePasswordWithDeliveryMechanisms()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id", "password",
              Arrays.asList("SMS", "Voice", "E-Mail"), controls);

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms(),
         Arrays.asList("SMS", "Voice", "E-Mail"));

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertEquals(r.getPreferredDeliveryMechanismNamesAndIDs().size(), 3);

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeOTP());

    assertNull(r.getFullTextAfterOTP());

    assertNull(r.getCompactTextBeforeOTP());

    assertNull(r.getCompactTextAfterOTP());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests a request containing all elements with the password as a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElementsStringPassword()
         throws Exception
  {
    final List<ObjectPair<String,String>> deliveryMechanisms =
         new ArrayList<ObjectPair<String,String>>(7);
    deliveryMechanisms.add(new ObjectPair<String,String>("SMS",
         "123-456-7890"));
    deliveryMechanisms.add(new ObjectPair<String,String>("SMS",
         "123-456-7891"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Voice", null));
    deliveryMechanisms.add(new ObjectPair<String,String>("Email",
         "john.doe@example.com"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Email",
         "jdoe@example.net"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Carrier Pigeon",
         null));
    deliveryMechanisms.add(new ObjectPair<String,String>("Mental Telepathy",
         null));

    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id", "password",
              "Message Subject", "Full Before", "Full After", "Compact Before",
              "Compact After", deliveryMechanisms,
              new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms(),
         Arrays.asList("SMS", "Voice", "Email", "Carrier Pigeon",
              "Mental Telepathy"));

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertEquals(r.getPreferredDeliveryMechanismNamesAndIDs(),
         deliveryMechanisms);

    assertNotNull(r.getMessageSubject());
    assertEquals(r.getMessageSubject(), "Message Subject");

    assertNotNull(r.getFullTextBeforeOTP());
    assertEquals(r.getFullTextBeforeOTP(), "Full Before");

    assertNotNull(r.getFullTextAfterOTP());
    assertEquals(r.getFullTextAfterOTP(), "Full After");

    assertNotNull(r.getCompactTextBeforeOTP());
    assertEquals(r.getCompactTextBeforeOTP(), "Compact Before");

    assertNotNull(r.getCompactTextAfterOTP());
    assertEquals(r.getCompactTextAfterOTP(), "Compact After");

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests a request containing all elements with a null string password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElementsNullStringPassword()
         throws Exception
  {
    final List<ObjectPair<String,String>> deliveryMechanisms =
         new ArrayList<ObjectPair<String,String>>(7);
    deliveryMechanisms.add(new ObjectPair<String,String>("SMS",
         "123-456-7890"));
    deliveryMechanisms.add(new ObjectPair<String,String>("SMS",
         "123-456-7891"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Voice", null));
    deliveryMechanisms.add(new ObjectPair<String,String>("Email",
         "john.doe@example.com"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Email",
         "jdoe@example.net"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Carrier Pigeon",
         null));
    deliveryMechanisms.add(new ObjectPair<String,String>("Mental Telepathy",
         null));

    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id", (String) null,
              "Message Subject", "Full Before", "Full After", "Compact Before",
              "Compact After", deliveryMechanisms,
              new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNull(r.getStaticPassword());

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms(),
         Arrays.asList("SMS", "Voice", "Email", "Carrier Pigeon",
              "Mental Telepathy"));

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertEquals(r.getPreferredDeliveryMechanismNamesAndIDs(),
         deliveryMechanisms);

    assertNotNull(r.getMessageSubject());
    assertEquals(r.getMessageSubject(), "Message Subject");

    assertNotNull(r.getFullTextBeforeOTP());
    assertEquals(r.getFullTextBeforeOTP(), "Full Before");

    assertNotNull(r.getFullTextAfterOTP());
    assertEquals(r.getFullTextAfterOTP(), "Full After");

    assertNotNull(r.getCompactTextBeforeOTP());
    assertEquals(r.getCompactTextBeforeOTP(), "Compact Before");

    assertNotNull(r.getCompactTextAfterOTP());
    assertEquals(r.getCompactTextAfterOTP(), "Compact After");

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests a request containing all elements with the password as a null byte
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElementsNullBytePassword()
         throws Exception
  {
    final List<ObjectPair<String,String>> deliveryMechanisms =
         new ArrayList<ObjectPair<String,String>>(7);
    deliveryMechanisms.add(new ObjectPair<String,String>("SMS",
         "123-456-7890"));
    deliveryMechanisms.add(new ObjectPair<String,String>("SMS",
         "123-456-7891"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Voice", null));
    deliveryMechanisms.add(new ObjectPair<String,String>("Email",
         "john.doe@example.com"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Email",
         "jdoe@example.net"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Carrier Pigeon",
         null));
    deliveryMechanisms.add(new ObjectPair<String,String>("Mental Telepathy",
         null));

    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id", (byte[]) null,
              "Message Subject", "Full Before", "Full After", "Compact Before",
              "Compact After", deliveryMechanisms, new Control("1.2.3.4"),
              new Control("1.2.3.5"));

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNull(r.getStaticPassword());

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms(),
         Arrays.asList("SMS", "Voice", "Email", "Carrier Pigeon",
              "Mental Telepathy"));

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertEquals(r.getPreferredDeliveryMechanismNamesAndIDs(),
         deliveryMechanisms);

    assertNotNull(r.getMessageSubject());
    assertEquals(r.getMessageSubject(), "Message Subject");

    assertNotNull(r.getFullTextBeforeOTP());
    assertEquals(r.getFullTextBeforeOTP(), "Full Before");

    assertNotNull(r.getFullTextAfterOTP());
    assertEquals(r.getFullTextAfterOTP(), "Full After");

    assertNotNull(r.getCompactTextBeforeOTP());
    assertEquals(r.getCompactTextBeforeOTP(), "Compact Before");

    assertNotNull(r.getCompactTextAfterOTP());
    assertEquals(r.getCompactTextAfterOTP(), "Compact After");

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests a request containing all elements with the password as a byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElementsBytePassword()
         throws Exception
  {
    final List<ObjectPair<String,String>> deliveryMechanisms =
         new ArrayList<ObjectPair<String,String>>(7);
    deliveryMechanisms.add(new ObjectPair<String,String>("SMS",
         "123-456-7890"));
    deliveryMechanisms.add(new ObjectPair<String,String>("SMS",
         "123-456-7891"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Voice", null));
    deliveryMechanisms.add(new ObjectPair<String,String>("Email",
         "john.doe@example.com"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Email",
         "jdoe@example.net"));
    deliveryMechanisms.add(new ObjectPair<String,String>("Carrier Pigeon",
         null));
    deliveryMechanisms.add(new ObjectPair<String,String>("Mental Telepathy",
         null));

    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id",
              "password".getBytes("UTF-8"), "Message Subject", "Full Before",
              "Full After", "Compact Before", "Compact After",
              deliveryMechanisms, new Control("1.2.3.4"),
              new Control("1.2.3.5"));

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms(),
         Arrays.asList("SMS", "Voice", "Email", "Carrier Pigeon",
              "Mental Telepathy"));

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertEquals(r.getPreferredDeliveryMechanismNamesAndIDs(),
         deliveryMechanisms);

    assertNotNull(r.getMessageSubject());
    assertEquals(r.getMessageSubject(), "Message Subject");

    assertNotNull(r.getFullTextBeforeOTP());
    assertEquals(r.getFullTextBeforeOTP(), "Full Before");

    assertNotNull(r.getFullTextAfterOTP());
    assertEquals(r.getFullTextAfterOTP(), "Full After");

    assertNotNull(r.getCompactTextBeforeOTP());
    assertEquals(r.getCompactTextBeforeOTP(), "Compact Before");

    assertNotNull(r.getCompactTextAfterOTP());
    assertEquals(r.getCompactTextAfterOTP(), "Compact After");

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the ability to decode a legacy request that includes only delivery
   * mechanism names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeLegacyRequest()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "u:auth.id"),
         new ASN1OctetString((byte) 0x81, "password"),
         new ASN1Sequence((byte) 0xA2,
              new ASN1OctetString("SMS"),
              new ASN1OctetString("Voice"),
              new ASN1OctetString("E-Mail")));

    DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest(
              new ExtendedRequest("1.3.6.1.4.1.30221.2.6.24",
                   new ASN1OctetString(valueSequence.encode())));

    r = new DeliverOneTimePasswordExtendedRequest(r.duplicate());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:auth.id");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNotNull(r.getPreferredDeliveryMechanisms());
    assertEquals(r.getPreferredDeliveryMechanisms(),
         Arrays.asList("SMS", "Voice", "E-Mail"));

    assertNotNull(r.getPreferredDeliveryMechanismNamesAndIDs());
    assertEquals(r.getPreferredDeliveryMechanismNamesAndIDs().size(), 3);

    assertNull(r.getMessageSubject());

    assertNull(r.getFullTextBeforeOTP());

    assertNull(r.getFullTextAfterOTP());

    assertNull(r.getCompactTextBeforeOTP());

    assertNull(r.getCompactTextAfterOTP());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.24");

    assertNotNull(r.getValue());

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
  public void testDecodeWithoutValue()
         throws Exception
  {
    new DeliverOneTimePasswordExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.24"));
  }



  /**
   * Tests the behavior when trying to decode an extended request whose value
   * cannot be decoded as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new DeliverOneTimePasswordExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.24", new ASN1OctetString("foo")));
  }



  /**
   * Tests the behavior when trying to decode an extended request when the value
   * sequence has an element with an unexpected type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "u:authid"),
         new ASN1OctetString((byte) 0x81, "password"),
         new ASN1OctetString((byte) 0x8F, "invalid"));

    new DeliverOneTimePasswordExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.24",
              new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode an extended request when the value
   * sequence does not include the authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMissingAuthID()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x81, "password"));

    new DeliverOneTimePasswordExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.24",
              new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to process the extended operation.  This
   * will fail, but will at least provide test coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessExtendedOperation()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final DeliverOneTimePasswordExtendedRequest extendedRequest =
         new DeliverOneTimePasswordExtendedRequest("u:auth.id", "password");
    assertResultCodeNot(conn, extendedRequest, ResultCode.SUCCESS);

    conn.close();
  }
}
