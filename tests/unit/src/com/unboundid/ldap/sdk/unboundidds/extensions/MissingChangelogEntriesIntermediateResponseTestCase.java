/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code MissingChangelogEntriesIntermediateResponse} class.
 */
public final class MissingChangelogEntriesIntermediateResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a missing changelog entries intermediate
   * response without a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testResponseWithoutMessage()
         throws Exception
  {
    MissingChangelogEntriesIntermediateResponse ir =
         new MissingChangelogEntriesIntermediateResponse((String) null);
    ir = new MissingChangelogEntriesIntermediateResponse(ir);

    assertNotNull(ir);

    assertNull(ir.getMessage());

    assertNotNull(ir.getIntermediateResponseName());

    assertNull(ir.valueToString());

    assertNotNull(ir.toString());
  }



  /**
   * Provides test coverage for a missing changelog entries intermediate
   * response with a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testResponseWithMessage()
         throws Exception
  {
    MissingChangelogEntriesIntermediateResponse ir =
         new MissingChangelogEntriesIntermediateResponse("foo",
              new Control("1.2.3.4"), new Control("5.6.7.8"));
    ir = new MissingChangelogEntriesIntermediateResponse(ir);

    assertNotNull(ir);

    assertNotNull(ir.getMessage());
    assertEquals(ir.getMessage(), "foo");

    assertNotNull(ir.getIntermediateResponseName());

    assertNotNull(ir.valueToString());

    assertNotNull(ir.toString());
  }



  /**
   * Provides test coverage for an attempt to decode a generic intermediate
   * response without a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeGenericResponseWithoutValue()
         throws Exception
  {
    final IntermediateResponse genericIR = new IntermediateResponse(
         MissingChangelogEntriesIntermediateResponse.
              MISSING_CHANGELOG_ENTRIES_INTERMEDIATE_RESPONSE_OID, null);
    final MissingChangelogEntriesIntermediateResponse mceIR =
         new MissingChangelogEntriesIntermediateResponse(genericIR);

    assertNotNull(mceIR);

    assertNull(mceIR.getMessage());

    assertNotNull(mceIR.getIntermediateResponseName());

    assertNull(mceIR.valueToString());

    assertNotNull(mceIR.toString());
  }



  /**
   * Provides test coverage for an attempt to decode a generic intermediate
   * response without a value that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new MissingChangelogEntriesIntermediateResponse(new IntermediateResponse(
         MissingChangelogEntriesIntermediateResponse.
              MISSING_CHANGELOG_ENTRIES_INTERMEDIATE_RESPONSE_OID,
         new ASN1OctetString("foo")));
  }



  /**
   * Provides test coverage for an attempt to decode a generic intermediate
   * response with a value that is an empty sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValueEmptySequence()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence();

    final IntermediateResponse genericIR = new IntermediateResponse(
         MissingChangelogEntriesIntermediateResponse.
              MISSING_CHANGELOG_ENTRIES_INTERMEDIATE_RESPONSE_OID,
         new ASN1OctetString(valueSequence.encode()));
    final MissingChangelogEntriesIntermediateResponse mceIR =
         new MissingChangelogEntriesIntermediateResponse(genericIR);

    assertNotNull(mceIR);

    assertNull(mceIR.getMessage());

    assertNotNull(mceIR.getIntermediateResponseName());

    assertNull(mceIR.valueToString());

    assertNotNull(mceIR.toString());
  }



  /**
   * Provides test coverage for an attempt to decode a generic intermediate
   * response with a value sequence with an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence =
         new ASN1Sequence(new ASN1OctetString((byte) 0x00, "foo"));

    new MissingChangelogEntriesIntermediateResponse(new IntermediateResponse(
         MissingChangelogEntriesIntermediateResponse.
              MISSING_CHANGELOG_ENTRIES_INTERMEDIATE_RESPONSE_OID,
         new ASN1OctetString(valueSequence.encode())));
  }
}
