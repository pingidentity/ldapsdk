/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.ByteArrayInputStream;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.LDAPMessage;



/**
 * This class provides a set of test cases for the ExtendedResult class.
 */
public class ExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor simulating a successful result with no OID
   * and no value.
   */
  @Test()
  public void testConstructor1SuccessNoOIDNoValue()
  {
    ExtendedResult extendedResult =
         new ExtendedResult(1, ResultCode.SUCCESS, null, null, null, null, null,
                            null);

    assertEquals(extendedResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(extendedResult.getDiagnosticMessage());

    assertNull(extendedResult.getMatchedDN());

    assertNotNull(extendedResult.getReferralURLs());
    assertEquals(extendedResult.getReferralURLs().length, 0);

    assertNotNull(extendedResult.getResponseControls());
    assertEquals(extendedResult.getResponseControls().length, 0);

    assertNull(extendedResult.getOID());

    assertNull(extendedResult.getValue());

    assertEquals(extendedResult.getMessageID(), 1);

    assertNull(extendedResult.getExtendedResultName());
    assertNotNull(extendedResult.toString());
  }



  /**
   * Tests the first constructor simulating a successful result with both an
   * OID and a value.
   */
  @Test()
  public void testConstructor1SuccessOIDAndValue()
  {
    ExtendedResult extendedResult =
         new ExtendedResult(1, ResultCode.SUCCESS, null, null, null, "4.3.2.1",
                            new ASN1OctetString(), null);

    assertEquals(extendedResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(extendedResult.getDiagnosticMessage());

    assertNull(extendedResult.getMatchedDN());

    assertNotNull(extendedResult.getReferralURLs());
    assertEquals(extendedResult.getReferralURLs().length, 0);

    assertNotNull(extendedResult.getResponseControls());
    assertEquals(extendedResult.getResponseControls().length, 0);

    assertNotNull(extendedResult.getOID());
    assertEquals(extendedResult.getOID(), "4.3.2.1");

    assertNotNull(extendedResult.getValue());

    assertEquals(extendedResult.getMessageID(), 1);

    assertNotNull(extendedResult.getExtendedResultName());
    assertNotNull(extendedResult.toString());
  }



  /**
   * Tests the first constructor simulating a failed result with no OID
   * and no value.
   */
  @Test()
  public void testConstructor1FailedNoOIDNoValue()
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ExtendedResult extendedResult =
         new ExtendedResult(1, ResultCode.NO_SUCH_OBJECT,
                            "The target entry does not exist",
                            "dc=example,dc=com", referralURLs, null, null,
                            controls);

    assertEquals(extendedResult.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(extendedResult.getDiagnosticMessage());
    assertEquals(extendedResult.getDiagnosticMessage(),
                 "The target entry does not exist");

    assertNotNull(extendedResult.getMatchedDN());
    assertEquals(extendedResult.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(extendedResult.getReferralURLs());
    assertEquals(extendedResult.getReferralURLs().length, 2);

    assertNotNull(extendedResult.getResponseControls());
    assertEquals(extendedResult.getResponseControls().length, 2);

    assertNull(extendedResult.getOID());

    assertNull(extendedResult.getValue());

    assertEquals(extendedResult.getMessageID(), 1);

    assertNull(extendedResult.getExtendedResultName());
    assertNotNull(extendedResult.toString());
  }



  /**
   * Tests the first constructor simulating a failed result with both an
   * OID and a value.
   */
  @Test()
  public void testConstructor1FailedOIDAndValue()
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ExtendedResult extendedResult =
         new ExtendedResult(1, ResultCode.NO_SUCH_OBJECT,
                            "The target entry does not exist",
                            "dc=example,dc=com", referralURLs, "4.3.2.1",
                            new ASN1OctetString(), controls);

    assertEquals(extendedResult.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(extendedResult.getDiagnosticMessage());
    assertEquals(extendedResult.getDiagnosticMessage(),
                 "The target entry does not exist");

    assertNotNull(extendedResult.getMatchedDN());
    assertEquals(extendedResult.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(extendedResult.getReferralURLs());
    assertEquals(extendedResult.getReferralURLs().length, 2);

    assertNotNull(extendedResult.getResponseControls());
    assertEquals(extendedResult.getResponseControls().length, 2);

    assertNotNull(extendedResult.getOID());
    assertEquals(extendedResult.getOID(), "4.3.2.1");

    assertNotNull(extendedResult.getValue());

    assertEquals(extendedResult.getMessageID(), 1);

    assertNotNull(extendedResult.getExtendedResultName());
    assertNotNull(extendedResult.toString());
  }



  /**
   * Tests the second constructor simulating a successful result with no OID
   * and no value.
   */
  @Test()
  public void testConstructor2SuccessNoOIDNoValue()
  {
    ExtendedResult result =
         new ExtendedResult(1, ResultCode.SUCCESS, null, null, null, null, null,
                            null);
    ExtendedResult extendedResult = new ExtendedResult(result);

    assertEquals(extendedResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(extendedResult.getDiagnosticMessage());

    assertNull(extendedResult.getMatchedDN());

    assertNotNull(extendedResult.getReferralURLs());
    assertEquals(extendedResult.getReferralURLs().length, 0);

    assertNotNull(extendedResult.getResponseControls());
    assertEquals(extendedResult.getResponseControls().length, 0);

    assertNull(extendedResult.getOID());

    assertNull(extendedResult.getValue());

    assertEquals(extendedResult.getMessageID(), 1);

    assertNull(extendedResult.getExtendedResultName());
    assertNotNull(extendedResult.toString());
  }



  /**
   * Tests the second constructor simulating a successful result with both an
   * OID and a value.
   */
  @Test()
  public void testConstructor2SuccessOIDAndValue()
  {
    ExtendedResult result =
         new ExtendedResult(1, ResultCode.SUCCESS, null, null, null, "4.3.2.1",
                            new ASN1OctetString(), null);
    ExtendedResult extendedResult = new ExtendedResult(result);

    assertEquals(extendedResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(extendedResult.getDiagnosticMessage());

    assertNull(extendedResult.getMatchedDN());

    assertNotNull(extendedResult.getReferralURLs());
    assertEquals(extendedResult.getReferralURLs().length, 0);

    assertNotNull(extendedResult.getResponseControls());
    assertEquals(extendedResult.getResponseControls().length, 0);

    assertNotNull(extendedResult.getOID());
    assertEquals(extendedResult.getOID(), "4.3.2.1");

    assertNotNull(extendedResult.getValue());

    assertEquals(extendedResult.getMessageID(), 1);

    assertNotNull(extendedResult.getExtendedResultName());
    assertNotNull(extendedResult.toString());
  }



  /**
   * Tests the second constructor simulating a failed result with no OID
   * and no value.
   */
  @Test()
  public void testConstructor2FailedNoOIDNoValue()
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ExtendedResult result =
         new ExtendedResult(1, ResultCode.NO_SUCH_OBJECT,
                            "The target entry does not exist",
                            "dc=example,dc=com", referralURLs, null, null,
                              controls);
    ExtendedResult extendedResult = new ExtendedResult(result);

    assertEquals(extendedResult.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(extendedResult.getDiagnosticMessage());
    assertEquals(extendedResult.getDiagnosticMessage(),
                 "The target entry does not exist");

    assertNotNull(extendedResult.getMatchedDN());
    assertEquals(extendedResult.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(extendedResult.getReferralURLs());
    assertEquals(extendedResult.getReferralURLs().length, 2);

    assertNotNull(extendedResult.getResponseControls());
    assertEquals(extendedResult.getResponseControls().length, 2);

    assertNull(extendedResult.getOID());

    assertNull(extendedResult.getValue());

    assertEquals(extendedResult.getMessageID(), 1);

    assertNull(extendedResult.getExtendedResultName());
    assertNotNull(extendedResult.toString());
  }



  /**
   * Tests the second constructor simulating a failed result with both an
   * OID and a value.
   */
  @Test()
  public void testConstructor2FailedOIDAndValue()
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ExtendedResult result =
         new ExtendedResult(1, ResultCode.NO_SUCH_OBJECT,
                            "The target entry does not exist",
                            "dc=example,dc=com", referralURLs, "4.3.2.1",
                              new ASN1OctetString(), controls);
    ExtendedResult extendedResult = new ExtendedResult(result);

    assertEquals(extendedResult.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(extendedResult.getDiagnosticMessage());
    assertEquals(extendedResult.getDiagnosticMessage(),
                 "The target entry does not exist");

    assertNotNull(extendedResult.getMatchedDN());
    assertEquals(extendedResult.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(extendedResult.getReferralURLs());
    assertEquals(extendedResult.getReferralURLs().length, 2);

    assertNotNull(extendedResult.getResponseControls());
    assertEquals(extendedResult.getResponseControls().length, 2);

    assertNotNull(extendedResult.getOID());
    assertEquals(extendedResult.getOID(), "4.3.2.1");

    assertNotNull(extendedResult.getValue());

    assertEquals(extendedResult.getMessageID(), 1);

    assertNotNull(extendedResult.getExtendedResultName());
    assertNotNull(extendedResult.toString());
  }



  /**
   * Tests the ability to create an extended result from an
   * {@code LDAPException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromException()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com/dc=example,dc=com",
      "ldap://ds2.example.com/dc=example,dc=com"
    };

    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5")
    };

    final LDAPException exception = new LDAPException(
         ResultCode.UNWILLING_TO_PERFORM,
         "Unknown extended request type '1.2.3.4'", "dc=example,dc=com",
         referralURLs, controls, new Exception("foo"));

    final ExtendedResult r = new ExtendedResult(exception);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(),"dc=example,dc=com");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the {@code readBindResultFrom} method with an element containing
   * a response sequence that is too short.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadExtendedResultFromTooShort()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);

    ASN1BufferSequence opSequence =
         b.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_RESPONSE);
    b.addEnumerated(0);
    opSequence.end();
    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }



  /**
   * Tests the {@code readBindResultFrom} method with a sequence containing an
   * invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadExtendedResultFromInvalidElementType()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);

    ASN1BufferSequence opSequence =
         b.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_RESPONSE);
    b.addEnumerated(0);
    b.addOctetString();
    b.addOctetString();
    b.addOctetString((byte) 0x00);
    opSequence.end();
    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }
}
