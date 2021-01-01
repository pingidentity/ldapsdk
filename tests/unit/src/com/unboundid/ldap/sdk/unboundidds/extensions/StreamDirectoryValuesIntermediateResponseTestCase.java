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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the stream directory values
 * intermediate response.
 */
public class StreamDirectoryValuesIntermediateResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a value containing a complete list of DNs
   * and no controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1CompleteDNListNoControls()
         throws Exception
  {
    StreamDirectoryValuesIntermediateResponse r =
         new StreamDirectoryValuesIntermediateResponse(null,
                  StreamDirectoryValuesIntermediateResponse.
                       RESULT_ALL_VALUES_RETURNED,
                  null,
                  Arrays.asList(new ASN1OctetString(""),
                       new ASN1OctetString("ou=People"),
                       new ASN1OctetString("uid=john.doe,ou=People")));
    r = new StreamDirectoryValuesIntermediateResponse(r);

    assertNull(r.getAttributeName());

    assertEquals(r.getResult(),
         StreamDirectoryValuesIntermediateResponse.RESULT_ALL_VALUES_RETURNED);

    assertNull(r.getDiagnosticMessage());

    assertNotNull(r.getValues());
    assertFalse(r.getValues().isEmpty());
    assertEquals(r.getValues().size(), 3);

    assertNotNull(r.getIntermediateResponseName());

    assertNotNull(r.valueToString());

    assertNotNull(r.toString());
  }



  /**
   * Tests the first constructor with a value containing a partial list of
   * values for the "givenName" attribute and a single control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1PartialGivenNameListSingleControl()
         throws Exception
  {
    StreamDirectoryValuesIntermediateResponse r =
         new StreamDirectoryValuesIntermediateResponse("givenName",
              StreamDirectoryValuesIntermediateResponse.
                   RESULT_MORE_VALUES_TO_RETURN,
              null,
              Arrays.asList(new ASN1OctetString("John"),
                   new ASN1OctetString("Johnathan"),
                   new ASN1OctetString("Jon")),
         new Control("1.2.3.4"));
    r = new StreamDirectoryValuesIntermediateResponse(r);

    assertNotNull(r.getAttributeName());
    assertEquals(r.getAttributeName(), "givenName");

    assertEquals(r.getResult(),
         StreamDirectoryValuesIntermediateResponse.
              RESULT_MORE_VALUES_TO_RETURN);

    assertNull(r.getDiagnosticMessage());

    assertNotNull(r.getValues());
    assertFalse(r.getValues().isEmpty());
    assertEquals(r.getValues().size(), 3);

    assertNotNull(r.getIntermediateResponseName());

    assertNotNull(r.valueToString());

    assertNotNull(r.toString());
  }



  /**
   * Tests the first constructor with an unindexed response for the "foo"
   * attribute, including multiple controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1UnindexedMultipleControls()
         throws Exception
  {
    StreamDirectoryValuesIntermediateResponse r =
         new StreamDirectoryValuesIntermediateResponse(
         "foo", StreamDirectoryValuesIntermediateResponse.
                   RESULT_ATTRIBUTE_NOT_INDEXED,
         "Attribute foo is not indexed for equality", null,
         new Control("1.2.3.4"), new Control("1.2.3.5"));
    r = new StreamDirectoryValuesIntermediateResponse(r);

    assertNotNull(r.getAttributeName());
    assertEquals(r.getAttributeName(), "foo");

    assertEquals(r.getResult(),
         StreamDirectoryValuesIntermediateResponse.
              RESULT_ATTRIBUTE_NOT_INDEXED);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(),
                 "Attribute foo is not indexed for equality");

    assertNotNull(r.getValues());
    assertTrue(r.getValues().isEmpty());

    assertNotNull(r.getIntermediateResponseName());

    assertNotNull(r.valueToString());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the second constructor with a response that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2NoValue()
         throws Exception
  {
    IntermediateResponse r = new IntermediateResponse(
         StreamDirectoryValuesIntermediateResponse.
              STREAM_DIRECTORY_VALUES_INTERMEDIATE_RESPONSE_OID,
         null);
    new StreamDirectoryValuesIntermediateResponse(r);
  }



  /**
   * Tests the behavior of the second constructor with a response whose value is
   * not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2ValueNotSequence()
         throws Exception
  {
    IntermediateResponse r = new IntermediateResponse(
         StreamDirectoryValuesIntermediateResponse.
              STREAM_DIRECTORY_VALUES_INTERMEDIATE_RESPONSE_OID,
         new ASN1OctetString("foo"));
    new StreamDirectoryValuesIntermediateResponse(r);
  }



  /**
   * Tests the behavior of the second constructor with a response whose value is
   * an empty sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2ValueEmptySequence()
         throws Exception
  {
    IntermediateResponse r = new IntermediateResponse(
         StreamDirectoryValuesIntermediateResponse.
              STREAM_DIRECTORY_VALUES_INTERMEDIATE_RESPONSE_OID,
         new ASN1OctetString(new ASN1Sequence().encode()));
    new StreamDirectoryValuesIntermediateResponse(r);
  }



  /**
   * Tests the behavior of the second constructor with a response whose value
   * contains an invalid result value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2ValueInvalidResult()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Enumerated((byte) 0x81, -1)
    };

    IntermediateResponse r = new IntermediateResponse(
         StreamDirectoryValuesIntermediateResponse.
              STREAM_DIRECTORY_VALUES_INTERMEDIATE_RESPONSE_OID,
         new ASN1OctetString(new ASN1Sequence(elements).encode()));
    new StreamDirectoryValuesIntermediateResponse(r);
  }



  /**
   * Tests the behavior of the second constructor with a response whose value
   * contains an element with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2ValueInvalidType()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Enumerated((byte) 0x81, 0),
      new ASN1OctetString((byte) 0x85, "foo")
    };

    IntermediateResponse r = new IntermediateResponse(
         StreamDirectoryValuesIntermediateResponse.
              STREAM_DIRECTORY_VALUES_INTERMEDIATE_RESPONSE_OID,
         new ASN1OctetString(new ASN1Sequence(elements).encode()));
    new StreamDirectoryValuesIntermediateResponse(r);
  }
}
