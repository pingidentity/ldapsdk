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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.ArrayList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * {@code UnboundIDDeliveredOTPBindRequest} class.
 */
public final class UnboundIDDeliveredOTPBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the bind request without an authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutAuthorizationID()
         throws Exception
  {
    UnboundIDDeliveredOTPBindRequest r = new UnboundIDDeliveredOTPBindRequest(
         "u:test.user", null, "123456");

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getOneTimePassword());
    assertEquals(r.getOneTimePassword(), "123456");

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-DELIVERED-OTP");

    assertEquals(r.getLastMessageID(), -1);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior of the bind request without an authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithAuthorizationID()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    UnboundIDDeliveredOTPBindRequest r = new UnboundIDDeliveredOTPBindRequest(
         "u:test.user", "u:authz.user", "abc123", controls);

    r = r.duplicate();
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:authz.user");

    assertNotNull(r.getOneTimePassword());
    assertEquals(r.getOneTimePassword(), "abc123");

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-DELIVERED-OTP");

    assertEquals(r.getLastMessageID(), -1);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior of the static methods used for encoding and decoding
   * SASL credentials without an authorization identity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeAndDecodeWithoutAuthorizationID()
         throws Exception
  {
    final ASN1OctetString encoded =
         UnboundIDDeliveredOTPBindRequest.encodeCredentials(
              "u:auth.id", null, "otp");
    assertNotNull(encoded);

    final UnboundIDDeliveredOTPBindRequest decoded =
         UnboundIDDeliveredOTPBindRequest.decodeSASLCredentials(encoded);

    assertNotNull(decoded.getAuthenticationID());
    assertEquals(decoded.getAuthenticationID(), "u:auth.id");

    assertNull(decoded.getAuthorizationID());

    assertNotNull(decoded.getOneTimePassword());
    assertEquals(decoded.getOneTimePassword(), "otp");

    assertNotNull(decoded.getSASLMechanismName());
    assertEquals(decoded.getSASLMechanismName(), "UNBOUNDID-DELIVERED-OTP");

    assertEquals(decoded.getLastMessageID(), -1);

    assertNotNull(decoded.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    decoded.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    decoded.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior of the static methods used for encoding and decoding
   * SASL credentials with an authorization identity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeAndDecodeWithAuthorizationID()
         throws Exception
  {
    final ASN1OctetString encoded =
         UnboundIDDeliveredOTPBindRequest.encodeCredentials(
              "u:auth.id", "u:authz.id", "otp");
    assertNotNull(encoded);

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    final UnboundIDDeliveredOTPBindRequest decoded =
         UnboundIDDeliveredOTPBindRequest.decodeSASLCredentials(encoded,
              controls);

    assertNotNull(decoded.getAuthenticationID());
    assertEquals(decoded.getAuthenticationID(), "u:auth.id");

    assertNotNull(decoded.getAuthorizationID());
    assertEquals(decoded.getAuthorizationID(), "u:authz.id");

    assertNotNull(decoded.getOneTimePassword());
    assertEquals(decoded.getOneTimePassword(), "otp");

    assertNotNull(decoded.getSASLMechanismName());
    assertEquals(decoded.getSASLMechanismName(), "UNBOUNDID-DELIVERED-OTP");

    assertEquals(decoded.getLastMessageID(), -1);

    assertNotNull(decoded.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    decoded.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    decoded.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior of the method for decoding SASL credentials when the
   * credentials cannot be decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    UnboundIDDeliveredOTPBindRequest.decodeSASLCredentials(
         new ASN1OctetString("foo"));
  }



  /**
   * Tests the behavior of the method for decoding SASL credentials when the
   * value sequence has an unexpected element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "u:auth.id"),
         new ASN1OctetString((byte) 0x82, "otp"),
         new ASN1OctetString((byte) 0x83, "foo"));

    UnboundIDDeliveredOTPBindRequest.decodeSASLCredentials(
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior of the method for decoding SASL credentials when the
   * value sequence is missing the authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMissingAuthID()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x82, "otp"));

    UnboundIDDeliveredOTPBindRequest.decodeSASLCredentials(
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior of the method for decoding SASL credentials when the
   * value sequence is missing the one-time password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMissingOTP()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "u:auth.id"));

    UnboundIDDeliveredOTPBindRequest.decodeSASLCredentials(
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to bind with this SASL mechanism.  This
   * will fail, but will at least provide test coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBind()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final UnboundIDDeliveredOTPBindRequest bindRequest =
         new UnboundIDDeliveredOTPBindRequest("u:auth.id", null, "otp");
    assertResultCodeEquals(conn, bindRequest,
         ResultCode.AUTH_METHOD_NOT_SUPPORTED);

    conn.close();
  }
}
