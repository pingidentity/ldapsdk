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

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code IntermediateResponseProtocolOp}
 * class.
 */
public class IntermediateResponseProtocolOpTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the intermediate response protocol op with an
   * OID but no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntermediateResponseProtocolOpWithOIDWithoutValue()
         throws Exception
  {
    IntermediateResponseProtocolOp op =
         new IntermediateResponseProtocolOp("1.2.3.4", null);
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new IntermediateResponseProtocolOp(reader);

    op = IntermediateResponseProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new IntermediateResponseProtocolOp(op.toIntermediateResponse());

    assertNotNull(op.getOID());
    assertEquals(op.getOID(), "1.2.3.4");

    assertNull(op.getValue());

    assertEquals(op.getProtocolOpType(), (byte) 0x79);

    assertNotNull(op.toString());
  }



  /**
   * Provides test coverage for the intermediate response protocol op with a
   * value but no OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntermediateResponseProtocolOpWithoutOIDWithValue()
         throws Exception
  {
    IntermediateResponseProtocolOp op =
         new IntermediateResponseProtocolOp(null, new ASN1OctetString());
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new IntermediateResponseProtocolOp(reader);

    op = IntermediateResponseProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new IntermediateResponseProtocolOp(op.toIntermediateResponse());

    assertNull(op.getOID());

    assertNotNull(op.getValue());
    assertEquals(op.getValue().getValue().length, 0);

    assertEquals(op.getProtocolOpType(), (byte) 0x79);

    assertNotNull(op.toString());
  }



  /**
   * Tests the behavior when trying to read a malformed intermediate response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadMalformedResponse()
         throws Exception
  {
    byte[] requestBytes = { (byte) 0x79 };
    ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new IntermediateResponseProtocolOp(reader);
  }



  /**
   * Tests the behavior when trying to decode a malformed intermediate response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedResponse()
         throws Exception
  {
    IntermediateResponseProtocolOp.decodeProtocolOp(
         new ASN1OctetString(LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE,
              "foo"));
  }



  /**
   * Tests the behavior when trying to read an intermediate response with an
   * invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadInvalidElementType()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence s = b.beginSequence((byte) 0x79);
    b.addOctetString((byte) 0x99);
    s.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new IntermediateResponseProtocolOp(reader);
  }



  /**
   * Tests the behavior when trying to decode an intermediate response with an
   * invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidElementType()
         throws Exception
  {
    final ASN1Sequence s = new ASN1Sequence(
         LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE,
         new ASN1OctetString((byte) 0x79));

    IntermediateResponseProtocolOp.decodeProtocolOp(s);
  }
}
