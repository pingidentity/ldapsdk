/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.ArrayList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the single-use variant of the
 * TOTP bind request.
 */
public final class SingleUseTOTPBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the minimal constructor and no static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoStaticStringPassword()
         throws Exception
  {
    SingleUseTOTPBindRequest r = new SingleUseTOTPBindRequest("u:john.doe",
         null, "123456", (String) null);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSASLCredentials());
    r = SingleUseTOTPBindRequest.decodeSASLCredentials(r.getSASLCredentials(),
         r.getControls());
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-TOTP");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:john.doe");

    assertNull(r.getAuthorizationID());

    assertNull(r.getStaticPassword());

    assertNotNull(r.getTOTPPassword());
    assertEquals(r.getTOTPPassword(), "123456");

    assertNull(r.getRebindRequest("127.0.0.1", 389));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the minimal constructor with a static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithStaticStringPassword()
         throws Exception
  {
    SingleUseTOTPBindRequest r = new SingleUseTOTPBindRequest("u:john.doe",
         "u:authz.user", "123456", "password", new Control("1.2.3.4"),
         new Control("1.2.3.5"));

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSASLCredentials());
    r = SingleUseTOTPBindRequest.decodeSASLCredentials(r.getSASLCredentials(),
         r.getControls());
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-TOTP");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:john.doe");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:authz.user");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNotNull(r.getTOTPPassword());
    assertEquals(r.getTOTPPassword(), "123456");

    assertNull(r.getRebindRequest("127.0.0.1", 389));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the minimal constructor and no static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoStaticByteArrayPassword()
         throws Exception
  {
    SingleUseTOTPBindRequest r = new SingleUseTOTPBindRequest("u:john.doe",
         null, "123456", (byte[]) null);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSASLCredentials());
    r = SingleUseTOTPBindRequest.decodeSASLCredentials(r.getSASLCredentials(),
         r.getControls());
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-TOTP");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:john.doe");

    assertNull(r.getAuthorizationID());

    assertNull(r.getStaticPassword());

    assertNotNull(r.getTOTPPassword());
    assertEquals(r.getTOTPPassword(), "123456");

    assertNull(r.getRebindRequest("127.0.0.1", 389));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the minimal constructor with a static password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithStaticByteArrayPassword()
         throws Exception
  {
    SingleUseTOTPBindRequest r = new SingleUseTOTPBindRequest("u:john.doe",
         "u:authz.user", "123456", "password".getBytes(),
         new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getSASLCredentials());
    r = SingleUseTOTPBindRequest.decodeSASLCredentials(r.getSASLCredentials(),
         r.getControls());
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-TOTP");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:john.doe");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:authz.user");

    assertNotNull(r.getStaticPassword());
    assertEquals(r.getStaticPassword().stringValue(), "password");

    assertNotNull(r.getTOTPPassword());
    assertEquals(r.getTOTPPassword(), "123456");

    assertNull(r.getRebindRequest("127.0.0.1", 389));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior of the method that can be used to decode a request from
   * credentials with a {@code null} set of credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNull()
         throws Exception
  {
    SingleUseTOTPBindRequest.decodeSASLCredentials(null);
  }



  /**
   * Tests the behavior of the method that can be used to decode a request from
   * credentials with a credentials value that cannot be decoded as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    SingleUseTOTPBindRequest.decodeSASLCredentials(new ASN1OctetString("foo"));
  }



  /**
   * Tests the behavior of the method that can be used to decode a request from
   * credentials with a credentials value that is an empty sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueEmptySequence()
         throws Exception
  {
    SingleUseTOTPBindRequest.decodeSASLCredentials(new ASN1OctetString(
         new ASN1Sequence().encode()));
  }



  /**
   * Tests the behavior of the method that can be used to decode a request from
   * credentials with a credentials value sequence that is missing an
   * authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMissingAuthenticationID()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(UnboundIDTOTPBindRequest.TYPE_TOTP_PASSWORD,
              "123456"));

    SingleUseTOTPBindRequest.decodeSASLCredentials(new ASN1OctetString(
         valueSequence.encode()));
  }



  /**
   * Tests the behavior of the method that can be used to decode a request from
   * credentials with a credentials value sequence that is missing a TOTP
   * password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMissingTOTPPassword()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(UnboundIDTOTPBindRequest.TYPE_AUTHENTICATION_ID,
              "u:john.doe"));

    SingleUseTOTPBindRequest.decodeSASLCredentials(new ASN1OctetString(
         valueSequence.encode()));
  }



  /**
   * Tests the behavior of the method that can be used to decode a request from
   * credentials with a credentials value sequence that has an element with an
   * invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(UnboundIDTOTPBindRequest.TYPE_AUTHENTICATION_ID,
              "u:john.doe"),
         new ASN1OctetString(UnboundIDTOTPBindRequest.TYPE_TOTP_PASSWORD,
              "123456"),
         new ASN1OctetString((byte) 0x00, "foo"));

    SingleUseTOTPBindRequest.decodeSASLCredentials(new ASN1OctetString(
         valueSequence.encode()));
  }



  /**
   * Provides basic coverage for the {@code process} method using a connection
   * that is not established.  This is expected to throw an exception, but will
   * nonetheless get code coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSendRequestOnDisconnectedConnection()
         throws Exception
  {
    final SingleUseTOTPBindRequest r =
         new SingleUseTOTPBindRequest("u:john.doe", null, "123456",
              "password");
    r.process(new LDAPConnection(), 1);
  }
}
