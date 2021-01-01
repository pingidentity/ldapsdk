/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the collect support data output
 * intermediate response.
 */
public final class CollectSupportDataOutputIntermediateResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a valid instance of the intermediate response with a standard
   * output message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStandardOutputMessage()
         throws Exception
  {
    CollectSupportDataOutputIntermediateResponse r =
         new CollectSupportDataOutputIntermediateResponse(
              CollectSupportDataOutputStream.STANDARD_OUTPUT, "foo");

    r = new CollectSupportDataOutputIntermediateResponse(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.65");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getOutputStream());
    assertEquals(r.getOutputStream(),
         CollectSupportDataOutputStream.STANDARD_OUTPUT);

    assertNotNull(r.getOutputMessage());
    assertEquals(r.getOutputMessage(), "foo");

    assertNotNull(r.getIntermediateResponseName());
    assertFalse(r.getIntermediateResponseName().isEmpty());

    assertNotNull(r.valueToString());
    assertFalse(r.valueToString().isEmpty());

    assertNotNull(r.toString());
    assertFalse(r.toString().isEmpty());
  }



  /**
   * Tests a valid instance of the intermediate response with a standard
   * error message and one control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStandardErrorMessageWithOneControl()
         throws Exception
  {
    CollectSupportDataOutputIntermediateResponse r =
         new CollectSupportDataOutputIntermediateResponse(
              CollectSupportDataOutputStream.STANDARD_ERROR, "bar",
              new Control("1.2.3.4"));

    r = new CollectSupportDataOutputIntermediateResponse(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.65");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getOutputStream());
    assertEquals(r.getOutputStream(),
         CollectSupportDataOutputStream.STANDARD_ERROR);

    assertNotNull(r.getOutputMessage());
    assertEquals(r.getOutputMessage(), "bar");

    assertNotNull(r.getIntermediateResponseName());
    assertFalse(r.getIntermediateResponseName().isEmpty());

    assertNotNull(r.valueToString());
    assertFalse(r.valueToString().isEmpty());

    assertNotNull(r.toString());
    assertFalse(r.toString().isEmpty());
  }



  /**
   * Tests a valid instance of the intermediate response with a standard
   * error message and multiple controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStandardErrorMessageWithMultipleControls()
         throws Exception
  {
    CollectSupportDataOutputIntermediateResponse r =
         new CollectSupportDataOutputIntermediateResponse(
              CollectSupportDataOutputStream.STANDARD_ERROR, "baz",
              new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new CollectSupportDataOutputIntermediateResponse(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.65");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getOutputStream());
    assertEquals(r.getOutputStream(),
         CollectSupportDataOutputStream.STANDARD_ERROR);

    assertNotNull(r.getOutputMessage());
    assertEquals(r.getOutputMessage(), "baz");

    assertNotNull(r.getIntermediateResponseName());
    assertFalse(r.getIntermediateResponseName().isEmpty());

    assertNotNull(r.valueToString());
    assertFalse(r.valueToString().isEmpty());

    assertNotNull(r.toString());
    assertFalse(r.toString().isEmpty());
  }



  /**
   * Tests the behavior when trying to decode an intermediate response that
   * does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeResponseWithoutValue()
         throws Exception
  {
    new CollectSupportDataOutputIntermediateResponse(
         new IntermediateResponse("1.3.6.1.4.1.30221.2.6.65", null));
  }



  /**
   * Tests the behavior when trying to decode an intermediate response that
   * has a malformed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeResponseWithMalformedValue()
         throws Exception
  {
    new CollectSupportDataOutputIntermediateResponse(
         new IntermediateResponse("1.3.6.1.4.1.30221.2.6.65",
              new ASN1OctetString("malformed")));
  }



  /**
   * Tests the behavior when trying to decode an intermediate response that
   * has an unrecognized output stream value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeResponseWithUnrecognizedOutputStream()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x80, 12345),
         new ASN1OctetString((byte) 0x81, "message"));
    final ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    new CollectSupportDataOutputIntermediateResponse(
         new IntermediateResponse("1.3.6.1.4.1.30221.2.6.65", value));
  }
}
