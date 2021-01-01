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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.ArrayList;
import java.util.List;

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
 * This class provides a number of test cases for the UNBOUNDID-YUBIKEY-OTP
 * bind request.
 */
public final class UnboundIDYubiKeyOTPBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the bind request with values provided for all fields,
   * using a static password provided as a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithAllFieldsStringStaticPassword()
         throws Exception
  {
    UnboundIDYubiKeyOTPBindRequest r = new UnboundIDYubiKeyOTPBindRequest(
         "dn:uid=test.user,ou=People,dc=example,dc=com",
         "u:authz.user", "password", "ThisIsMyYubiKeyOTP",
         new Control("1.2.3.4"), new Control("5.6.7.8"));

    r = r.duplicate();
    assertNotNull(r);

    r = UnboundIDYubiKeyOTPBindRequest.decodeCredentials(
         r.encodeCredentials(), r.getControls());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(),
         "dn:uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:authz.user");

    assertNotNull(r.getStaticPasswordString());
    assertEquals(r.getStaticPasswordString(), "password");

    assertNotNull(r.getStaticPasswordBytes());
    assertEquals(r.getStaticPasswordBytes(), "password".getBytes("UTF-8"));

    assertNotNull(r.getYubiKeyOTP());
    assertEquals(r.getYubiKeyOTP(), "ThisIsMyYubiKeyOTP");

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-YUBIKEY-OTP");

    r.getLastMessageID();

    assertNotNull(r.toString());

    final List<String> toCodeLines = new ArrayList<>();
    r.toCode(toCodeLines, "testRequestID", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior of the bind request with values provided for all fields,
   * using a static password provided as a byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithAllFieldsByteArrayStaticPassword()
         throws Exception
  {
    UnboundIDYubiKeyOTPBindRequest r = new UnboundIDYubiKeyOTPBindRequest(
         "dn:uid=test.user,ou=People,dc=example,dc=com",
         "u:authz.user", "password".getBytes("UTF-8"), "ThisIsMyYubiKeyOTP",
         new Control("1.2.3.4"), new Control("5.6.7.8"));

    r = r.duplicate();
    assertNotNull(r);

    r = UnboundIDYubiKeyOTPBindRequest.decodeCredentials(
         r.encodeCredentials(), r.getControls());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(),
         "dn:uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:authz.user");

    assertNotNull(r.getStaticPasswordString());
    assertEquals(r.getStaticPasswordString(), "password");

    assertNotNull(r.getStaticPasswordBytes());
    assertEquals(r.getStaticPasswordBytes(), "password".getBytes("UTF-8"));

    assertNotNull(r.getYubiKeyOTP());
    assertEquals(r.getYubiKeyOTP(), "ThisIsMyYubiKeyOTP");

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-YUBIKEY-OTP");

    r.getLastMessageID();

    assertNotNull(r.toString());

    final List<String> toCodeLines = new ArrayList<>();
    r.toCode(toCodeLines, "testRequestID", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior of the bind request with the minimal set of arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalRequest()
         throws Exception
  {
    UnboundIDYubiKeyOTPBindRequest r = new UnboundIDYubiKeyOTPBindRequest(
         "dn:uid=test.user,ou=People,dc=example,dc=com", null, (String) null,
         "ThisIsMyYubiKeyOTP", new Control("1.2.3.4"), new Control("5.6.7.8"));

    r = r.duplicate();
    assertNotNull(r);

    r = UnboundIDYubiKeyOTPBindRequest.decodeCredentials(
         r.encodeCredentials(), r.getControls());
    assertNotNull(r);

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(),
         "dn:uid=test.user,ou=People,dc=example,dc=com");

    assertNull(r.getAuthorizationID());

    assertNull(r.getStaticPasswordString());

    assertNull(r.getStaticPasswordBytes());

    assertNotNull(r.getYubiKeyOTP());
    assertEquals(r.getYubiKeyOTP(), "ThisIsMyYubiKeyOTP");

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "UNBOUNDID-YUBIKEY-OTP");

    r.getLastMessageID();

    assertNotNull(r.toString());

    final List<String> toCodeLines = new ArrayList<>();
    r.toCode(toCodeLines, "testRequestID", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior when trying to decode a bind request with malformed
   * credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedCredentials()
         throws Exception
  {
    UnboundIDYubiKeyOTPBindRequest.decodeCredentials(
         new ASN1OctetString("malformed"));
  }



  /**
   * Tests the behavior when trying to decode a bind request with valid
   * credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidCredentials()
         throws Exception
  {
    final ASN1Sequence credSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "u:authid"),
         new ASN1OctetString((byte) 0x83, "ThisIsMyYubiKeyOTP"));

    final UnboundIDYubiKeyOTPBindRequest r =
         UnboundIDYubiKeyOTPBindRequest.decodeCredentials(
              new ASN1OctetString(credSequence.encode()));

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:authid");

    assertNull(r.getAuthorizationID());

    assertNull(r.getStaticPasswordString());

    assertNull(r.getStaticPasswordBytes());

    assertNotNull(r.getYubiKeyOTP());
    assertEquals(r.getYubiKeyOTP(), "ThisIsMyYubiKeyOTP");

    assertNotNull(r.toString());

    final List<String> toCodeLines = new ArrayList<>();
    r.toCode(toCodeLines, "testRequestID", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the behavior when trying to decode a bind request whose credential
   * sequence includes an element with an unrecognized BER type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeUnrecognizedElementType()
         throws Exception
  {
    final ASN1Sequence credSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "u:authid"),
         new ASN1OctetString((byte) 0x83, "ThisIsMyYubiKeyOTP"),
         new ASN1OctetString((byte) 0x00, "Unrecognized Type"));

    UnboundIDYubiKeyOTPBindRequest.decodeCredentials(
         new ASN1OctetString(credSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a bind request that does not
   * include an authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingAuthenticationID()
         throws Exception
  {
    final ASN1Sequence credSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x83, "ThisIsMyYubiKeyOTP"));

    UnboundIDYubiKeyOTPBindRequest.decodeCredentials(
         new ASN1OctetString(credSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a bind request that does not
   * include a YubiKey OTP.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingYubiKeyOTP()
         throws Exception
  {
    final ASN1Sequence credSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "u:authid"));

    UnboundIDYubiKeyOTPBindRequest.decodeCredentials(
         new ASN1OctetString(credSequence.encode()));
  }



  /**
   * Provides test coverage for the {@code process} method.  This won't succeed
   * because the in-memory server doesn't have support for this SASL mechanism,
   * but it will at least get coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcess()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    assertResultCodeNot(conn,
         new UnboundIDYubiKeyOTPBindRequest("u:test.user", null, "password",
              "ThisIsMyYubiKeyOTP"),
         ResultCode.SUCCESS);

    conn.close();
  }
}
