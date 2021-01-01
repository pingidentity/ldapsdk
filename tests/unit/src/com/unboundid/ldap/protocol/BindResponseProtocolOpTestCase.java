/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.protocol;



import java.io.ByteArrayInputStream;
import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code BindResponseProtocolOp} class.
 */
public class BindResponseProtocolOpTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the bind response protocol op for a success
   * response, including server SASL credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindResponseProtocolOpSuccess()
         throws Exception
  {
    BindResponseProtocolOp op = new BindResponseProtocolOp(0, null, null, null,
        new ASN1OctetString());

    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new BindResponseProtocolOp(reader);

    op = BindResponseProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new BindResponseProtocolOp(op.toBindResult());

    assertEquals(op.getResultCode(), 0);

    assertNull(op.getMatchedDN());

    assertNull(op.getDiagnosticMessage());

    assertNotNull(op.getReferralURLs());
    assertTrue(op.getReferralURLs().isEmpty());

    assertNotNull(op.getServerSASLCredentials());
    assertEquals(op.getServerSASLCredentials().getValue().length, 0);

    assertEquals(op.getProtocolOpType(), (byte) 0x61);

    assertNotNull(op.toString());
  }



  /**
   * Provides test coverage for the bind response protocol op for a failure
   * response with no server SASL credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindResponseProtocolOpFailure()
         throws Exception
  {
    LinkedList<String> refs = new LinkedList<String>();
    refs.add("ldap://server1.example.com:389/dc=example,dc=com");
    refs.add("ldap://server2.example.com:389/dc=example,dc=com");

    BindResponseProtocolOp op = new BindResponseProtocolOp(32,
         "dc=example,dc=com", "The parent entry did not exist", refs, null);

    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new BindResponseProtocolOp(reader);

    op = BindResponseProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new BindResponseProtocolOp(op.toBindResult());

    assertEquals(op.getResultCode(), 32);

    assertNotNull(op.getMatchedDN());
    assertEquals(new DN(op.getMatchedDN()),
         new DN("dc=example,dc=com"));

    assertNotNull(op.getDiagnosticMessage());
    assertEquals(op.getDiagnosticMessage(), "The parent entry did not exist");

    assertNotNull(op.getReferralURLs());
    assertFalse(op.getReferralURLs().isEmpty());
    assertEquals(op.getReferralURLs().size(), 2);

    assertNull(op.getServerSASLCredentials());

    assertEquals(op.getProtocolOpType(), (byte) 0x61);

    assertNotNull(op.toString());
  }



  /**
   * Tests the behavior when attempting to create a bind response protocol
   * op from a generic LDAP result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromGenericLDAPResult()
         throws Exception
  {
    final LDAPResult r = new LDAPResult(-1, ResultCode.UNWILLING_TO_PERFORM,
         "I'm not going to process that.", null, null, StaticUtils.NO_CONTROLS);
    final BindResponseProtocolOp op = new BindResponseProtocolOp(r);

    assertEquals(op.getResultCode(), 53);

    assertNull(op.getMatchedDN());

    assertNotNull(op.getDiagnosticMessage());
    assertEquals(op.getDiagnosticMessage(),
         "I'm not going to process that.");

    assertNotNull(op.getReferralURLs());
    assertTrue(op.getReferralURLs().isEmpty());

    assertNull(op.getServerSASLCredentials());

    assertEquals(op.getProtocolOpType(), (byte) 0x61);

    assertNotNull(op.toString());
  }



  /**
   * Tests the behavior when trying to read a malformed bind response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadMalformedBindResponse()
         throws Exception
  {
    byte[] opBytes = { 0x61, 0x00 };
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new BindResponseProtocolOp(reader);
  }



  /**
   * Tests the behavior when trying to decode a malformed bind response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedBindResponse()
         throws Exception
  {
    BindResponseProtocolOp.decodeProtocolOp(
         new ASN1Element(LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE));
  }



  /**
   * Tests the behavior when trying to read a bind response with an invalid
   * element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadBindResponseInvalidElementType()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer((byte) 0x61);
    ASN1BufferSequence s = b.beginSequence();
    b.addEnumerated(0);
    b.addOctetString();
    b.addOctetString();
    b.addOctetString((byte) 0x80);
    s.end();


    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new BindResponseProtocolOp(reader);
  }



  /**
   * Tests the behavior when trying to decode a bind response with an invalid
   * element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeBindResponseInvalidElementType()
         throws Exception
  {
    final ASN1Sequence s = new ASN1Sequence(
         LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE,
         new ASN1Enumerated(0),
         new ASN1OctetString(),
         new ASN1OctetString(),
         new ASN1OctetString((byte) 0x80));

    BindResponseProtocolOp.decodeProtocolOp(s);
  }
}
