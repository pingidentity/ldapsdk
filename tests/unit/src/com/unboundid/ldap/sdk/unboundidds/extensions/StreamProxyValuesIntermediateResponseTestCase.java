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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code StreamProxyValuesIntermediateResponse} class.
 */
public class StreamProxyValuesIntermediateResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a success response with information about entry
   * DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessDNs()
         throws Exception
  {
    LinkedList<StreamProxyValuesBackendSetValue> values =
         new LinkedList<StreamProxyValuesBackendSetValue>();
    values.add(new StreamProxyValuesBackendSetValue(
         new ASN1OctetString("a"),
         new ASN1OctetString("ou=a,dc=example,dc=com")));
    values.add(new StreamProxyValuesBackendSetValue(
         new ASN1OctetString("b"),
         new ASN1OctetString("ou=b,dc=example,dc=com")));

    StreamProxyValuesIntermediateResponse r =
         new StreamProxyValuesIntermediateResponse(null,
                  StreamProxyValuesIntermediateResponse.
                       RESULT_ALL_VALUES_RETURNED,
                  null, values);
    r = new StreamProxyValuesIntermediateResponse(new IntermediateResponse(
         r.getOID(), r.getValue(), r.getControls()));

    assertNotNull(r);

    assertNull(r.getAttributeName());

    assertEquals(r.getResult(),
         StreamProxyValuesIntermediateResponse.RESULT_ALL_VALUES_RETURNED);

    assertNull(r.getDiagnosticMessage());

    assertNotNull(r.getValues());
    assertEquals(r.getValues().size(), 2);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getIntermediateResponseName());

    assertNotNull(r.valueToString());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a success response with information about
   * attribute values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessAttributeValues()
         throws Exception
  {
    LinkedList<StreamProxyValuesBackendSetValue> values =
         new LinkedList<StreamProxyValuesBackendSetValue>();
    values.add(new StreamProxyValuesBackendSetValue(
         new ASN1OctetString("a"), new ASN1OctetString("a")));
    values.add(new StreamProxyValuesBackendSetValue(
         new ASN1OctetString("b"), new ASN1OctetString("b")));

    StreamProxyValuesIntermediateResponse r =
         new StreamProxyValuesIntermediateResponse("uid",
                  StreamProxyValuesIntermediateResponse.
                       RESULT_MORE_VALUES_TO_RETURN,
                  null, values, new Control("1.2.3.4"));
    r = new StreamProxyValuesIntermediateResponse(new IntermediateResponse(
         r.getOID(), r.getValue(), r.getControls()));

    assertNotNull(r);

    assertNotNull(r.getAttributeName());
    assertEquals(r.getAttributeName(), "uid");

    assertEquals(r.getResult(),
         StreamProxyValuesIntermediateResponse.RESULT_MORE_VALUES_TO_RETURN);

    assertNull(r.getDiagnosticMessage());

    assertNotNull(r.getValues());
    assertEquals(r.getValues().size(), 2);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getIntermediateResponseName());

    assertNotNull(r.valueToString());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for an error response with an "attribute not
   * indexed" result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureAttributeNotIndexed()
         throws Exception
  {
    StreamProxyValuesIntermediateResponse r =
         new StreamProxyValuesIntermediateResponse("unindexed",
                  StreamProxyValuesIntermediateResponse.
                       RESULT_ATTRIBUTE_NOT_INDEXED,
                  "Attribute unindexed is not indexed", null,
                  new Control("1.2.3.4"), new Control("1.2.3.5"));
    r = new StreamProxyValuesIntermediateResponse(new IntermediateResponse(
         r.getOID(), r.getValue(), r.getControls()));

    assertNotNull(r);

    assertNotNull(r.getAttributeName());
    assertEquals(r.getAttributeName(), "unindexed");

    assertEquals(r.getResult(),
         StreamProxyValuesIntermediateResponse.RESULT_ATTRIBUTE_NOT_INDEXED);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(),
                 "Attribute unindexed is not indexed");

    assertNotNull(r.getValues());
    assertTrue(r.getValues().isEmpty());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getIntermediateResponseName());

    assertNotNull(r.valueToString());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an intermediate response with no
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    IntermediateResponse r = new IntermediateResponse(
         "1.3.6.1.4.1.30221.2.6.9", (ASN1OctetString) null);
    new StreamProxyValuesIntermediateResponse(r);
  }



  /**
   * Tests the behavior when trying to decode an intermediate response with a
   * malformed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedValue()
         throws Exception
  {
    IntermediateResponse r = new IntermediateResponse(
         "1.3.6.1.4.1.30221.2.6.9", new ASN1OctetString("foo"));
    new StreamProxyValuesIntermediateResponse(r);
  }



  /**
   * Tests the behavior when trying to decode an intermediate response with an
   * empty value sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeEmptyValueSequence()
         throws Exception
  {
    ASN1Sequence valueSequence = new ASN1Sequence();

    ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    IntermediateResponse r = new IntermediateResponse(
         "1.3.6.1.4.1.30221.2.6.9", value);
    new StreamProxyValuesIntermediateResponse(r);
  }



  /**
   * Tests the behavior when trying to decode an intermediate response with a
   * malformed result element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedResult()
         throws Exception
  {
    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x81));

    ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    IntermediateResponse r = new IntermediateResponse(
         "1.3.6.1.4.1.30221.2.6.9", value);
    new StreamProxyValuesIntermediateResponse(r);
  }



  /**
   * Tests the behavior when trying to decode an intermediate response with an
   * invalid result value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidResult()
         throws Exception
  {
    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x81, -1));

    ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    IntermediateResponse r = new IntermediateResponse(
         "1.3.6.1.4.1.30221.2.6.9", value);
    new StreamProxyValuesIntermediateResponse(r);
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
    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x81, 0),
         new ASN1OctetString((byte) 0x8F));

    ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    IntermediateResponse r = new IntermediateResponse(
         "1.3.6.1.4.1.30221.2.6.9", value);
    new StreamProxyValuesIntermediateResponse(r);
  }
}
