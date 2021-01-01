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
import java.util.LinkedHashMap;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Boolean;
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
 * {@code UnboundIDExternallyProcessedAuthenticationBindRequest} class.
 */
public final class UnboundIDExternallyProcessedAuthenticationBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a bind request that represents a successful
   * authentication attempt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSuccessRequest()
         throws Exception
  {
    UnboundIDExternallyProcessedAuthenticationBindRequest r =
         new UnboundIDExternallyProcessedAuthenticationBindRequest(
              "dn:uid=test.user,ou=People,dc=example,dc=com", "TEST", true,
              null, false, false, null, null);

    r = r.duplicate();
    assertNotNull(r);

    r = r.getRebindRequest("localhost", 389);
    assertNotNull(r);

    r = UnboundIDExternallyProcessedAuthenticationBindRequest.
         decodeSASLCredentials(r.getEncodedCredentials(), r.getControls());
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(),
         "UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(),
         "dn:uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getExternalMechanismName());
    assertEquals(r.getExternalMechanismName(), "TEST");

    assertTrue(r.externalAuthenticationWasSuccessful());

    assertNull(r.getExternalAuthenticationFailureReason());

    assertFalse(r.externalAuthenticationWasPasswordBased());

    assertFalse(r.externalAuthenticationWasSecure());

    assertNull(r.getEndClientIPAddress());

    assertNotNull(r.getAdditionalAccessLogProperties());
    assertTrue(r.getAdditionalAccessLogProperties().isEmpty());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLineList = new ArrayList<String>(10);
    r.toCode(toCodeLineList, "testMinimalConstructorSuccess", 0, false);
    assertFalse(toCodeLineList.isEmpty());
  }



  /**
   * Tests the behavior with a bind request that represents a failed
   * authentication attempt with a minimal set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFailureRequestMinimal()
         throws Exception
  {
    UnboundIDExternallyProcessedAuthenticationBindRequest r =
         new UnboundIDExternallyProcessedAuthenticationBindRequest(
              "u:test.user", "TEST", false, null, true, false, null, null);

    r = r.duplicate();
    assertNotNull(r);

    r = r.getRebindRequest("localhost", 389);
    assertNotNull(r);

    r = UnboundIDExternallyProcessedAuthenticationBindRequest.
         decodeSASLCredentials(r.getEncodedCredentials(), r.getControls());
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(),
         "UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getExternalMechanismName());
    assertEquals(r.getExternalMechanismName(), "TEST");

    assertFalse(r.externalAuthenticationWasSuccessful());

    assertNull(r.getExternalAuthenticationFailureReason());

    assertTrue(r.externalAuthenticationWasPasswordBased());

    assertFalse(r.externalAuthenticationWasSecure());

    assertNull(r.getEndClientIPAddress());

    assertNotNull(r.getAdditionalAccessLogProperties());
    assertTrue(r.getAdditionalAccessLogProperties().isEmpty());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLineList = new ArrayList<String>(10);
    r.toCode(toCodeLineList, "testMinimalConstructorSuccess", 0, true);
    assertFalse(toCodeLineList.isEmpty());
  }



  /**
   * Tests the behavior with a bind request that represents a failed
   * authentication attempt with a full set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFailureRequestFull()
         throws Exception
  {
    final LinkedHashMap<String,String> logProperties =
         new LinkedHashMap<String,String>(2);
    logProperties.put("name1", "value1");
    logProperties.put("name2", "value2");

    UnboundIDExternallyProcessedAuthenticationBindRequest r =
         new UnboundIDExternallyProcessedAuthenticationBindRequest(
              "u:test.user", "TEST", false, "It didn't work", false, true,
              "127.0.0.1", logProperties, new Control("1.2.3.4"),
              new Control("5.6.7.8"));

    r = r.duplicate();
    assertNotNull(r);

    r = r.getRebindRequest("localhost", 389);
    assertNotNull(r);

    r = UnboundIDExternallyProcessedAuthenticationBindRequest.
         decodeSASLCredentials(r.getEncodedCredentials(), r.getControls());
    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(),
         "UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getExternalMechanismName());
    assertEquals(r.getExternalMechanismName(), "TEST");

    assertFalse(r.externalAuthenticationWasSuccessful());

    assertNotNull(r.getExternalAuthenticationFailureReason());
    assertEquals(r.getExternalAuthenticationFailureReason(), "It didn't work");

    assertFalse(r.externalAuthenticationWasPasswordBased());

    assertTrue(r.externalAuthenticationWasSecure());

    assertNotNull(r.getEndClientIPAddress());
    assertEquals(r.getEndClientIPAddress(), "127.0.0.1");

    assertNotNull(r.getAdditionalAccessLogProperties());
    assertEquals(r.getAdditionalAccessLogProperties().size(), 2);
    assertEquals(r.getAdditionalAccessLogProperties().get("name1"), "value1");
    assertEquals(r.getAdditionalAccessLogProperties().get("name2"), "value2");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLineList = new ArrayList<String>(10);
    r.toCode(toCodeLineList, "testMinimalConstructorSuccess", 5, true);
    assertFalse(toCodeLineList.isEmpty());
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that represents
   * a valid set of encoded credentials with a minimal encoding.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidMinimalCredentials()
         throws Exception
  {
    final ASN1Sequence credSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80,
              "dn:uid=test.user,ou=People,dc=example,dc=com"),
         new ASN1OctetString((byte) 0x81, "TEST"),
         new ASN1Boolean((byte) 0x82, true));

    final UnboundIDExternallyProcessedAuthenticationBindRequest r =
         UnboundIDExternallyProcessedAuthenticationBindRequest.
              decodeSASLCredentials(new ASN1OctetString(credSequence.encode()));

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(),
         "UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(),
         "dn:uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(r.getExternalMechanismName());
    assertEquals(r.getExternalMechanismName(), "TEST");

    assertTrue(r.externalAuthenticationWasSuccessful());

    assertNull(r.getExternalAuthenticationFailureReason());

    assertTrue(r.externalAuthenticationWasPasswordBased());

    assertFalse(r.externalAuthenticationWasSecure());

    assertNull(r.getEndClientIPAddress());

    assertNotNull(r.getAdditionalAccessLogProperties());
    assertTrue(r.getAdditionalAccessLogProperties().isEmpty());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLineList = new ArrayList<String>(10);
    r.toCode(toCodeLineList, "testMinimalConstructorSuccess", 0, false);
    assertFalse(toCodeLineList.isEmpty());
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that represents
   * a valid set of encoded credentials with a full encoding.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidFullCredentials()
         throws Exception
  {
    final ASN1Sequence credSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "u:test.user"),
         new ASN1OctetString((byte) 0x81, "TEST"),
         new ASN1Boolean((byte) 0x82, false),
         new ASN1OctetString((byte) 0x83, "It didn't work"),
         new ASN1Boolean((byte) 0x84, true),
         new ASN1Boolean((byte) 0x85, true),
         new ASN1OctetString((byte) 0x86, "127.0.0.1"),
         new ASN1Sequence((byte) 0xA7,
              new ASN1Sequence(
                   new ASN1OctetString("name1"),
                   new ASN1OctetString("value1")),
              new ASN1Sequence(
                   new ASN1OctetString("name2"),
                   new ASN1OctetString("value2"))));

    final UnboundIDExternallyProcessedAuthenticationBindRequest r =
         UnboundIDExternallyProcessedAuthenticationBindRequest.
              decodeSASLCredentials(new ASN1OctetString(credSequence.encode()),
                   new Control("1.2.3.4"), new Control("5.6.7.8"));

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(),
         "UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getExternalMechanismName());
    assertEquals(r.getExternalMechanismName(), "TEST");

    assertFalse(r.externalAuthenticationWasSuccessful());

    assertNotNull(r.getExternalAuthenticationFailureReason());
    assertEquals(r.getExternalAuthenticationFailureReason(), "It didn't work");

    assertTrue(r.externalAuthenticationWasPasswordBased());

    assertTrue(r.externalAuthenticationWasSecure());

    assertNotNull(r.getEndClientIPAddress());
    assertEquals(r.getEndClientIPAddress(), "127.0.0.1");

    assertNotNull(r.getAdditionalAccessLogProperties());
    assertEquals(r.getAdditionalAccessLogProperties().size(), 2);
    assertEquals(r.getAdditionalAccessLogProperties().get("name1"), "value1");
    assertEquals(r.getAdditionalAccessLogProperties().get("name2"), "value2");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLineList = new ArrayList<String>(10);
    r.toCode(toCodeLineList, "testMinimalConstructorSuccess", 5, true);
    assertFalse(toCodeLineList.isEmpty());
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that does not
   * represent valid UNBOUNDID-EXTERNALLY-PROCESSED-AUTHENTICATION credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedCredentials()
         throws Exception
  {
    UnboundIDExternallyProcessedAuthenticationBindRequest.decodeSASLCredentials(
         new ASN1OctetString("malformed"));
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that represents
   * encoded credentials that would be valid except that it is missing the
   * required userDN element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeCredentialsMissingUserDN()
         throws Exception
  {
    final ASN1Sequence credSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x81, "TEST"),
         new ASN1Boolean((byte) 0x82, true));

    UnboundIDExternallyProcessedAuthenticationBindRequest.decodeSASLCredentials(
         new ASN1OctetString(credSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that represents
   * encoded credentials that would be valid except that it is missing the
   * required externalMechanismName element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeCredentialsMissingExternalMechanismName()
         throws Exception
  {
    final ASN1Sequence credSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80,
              "dn:uid=test.user,ou=People,dc=example,dc=com"),
         new ASN1Boolean((byte) 0x82, true));

    UnboundIDExternallyProcessedAuthenticationBindRequest.decodeSASLCredentials(
         new ASN1OctetString(credSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that represents
   * encoded credentials that would be valid except that it is missing the
   * required externalAuthenticationIsSuccessful element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeCredentialsMissingExternalAuthenticationIsSuccessful()
         throws Exception
  {
    final ASN1Sequence credSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80,
              "dn:uid=test.user,ou=People,dc=example,dc=com"),
         new ASN1OctetString((byte) 0x81, "TEST"));

    UnboundIDExternallyProcessedAuthenticationBindRequest.decodeSASLCredentials(
         new ASN1OctetString(credSequence.encode()));
  }



  /**
   * Tests the behavior when trying to process the bind operation.  The
   * in-memory directory server doesn't support this SASL mechanism, but this
   * will at least get test coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcess()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final UnboundIDExternallyProcessedAuthenticationBindRequest bindRequest =
         new UnboundIDExternallyProcessedAuthenticationBindRequest(
              "dn:uid=test.user,ou=People,dc=example,dc=com", "TEST", true,
              null, true, true, "1.2.3.4", null);

    final LDAPConnection conn = ds.getConnection();

    try
    {
      conn.bind(bindRequest);
      fail("Expected a failure when trying to process a SASL bind request " +
           "with an unsupported SASL mechanism");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.AUTH_METHOD_NOT_SUPPORTED);
    }
    finally
    {
      conn.close();
    }

    assertTrue(bindRequest.getLastMessageID() > 0);
  }
}
