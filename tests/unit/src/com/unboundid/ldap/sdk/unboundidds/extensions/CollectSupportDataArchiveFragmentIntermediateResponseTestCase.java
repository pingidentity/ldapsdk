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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the collect support data archive
 * fragment intermediate response.
 */
public final class CollectSupportDataArchiveFragmentIntermediateResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a valid instance of the intermediate response with more data to
   * return.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidResponseWithMoreToReturn()
         throws Exception
  {
    CollectSupportDataArchiveFragmentIntermediateResponse r =
         new CollectSupportDataArchiveFragmentIntermediateResponse("csd.zip",
              123_456L, true, StaticUtils.byteArray(1, 2, 3, 4, 5, 6, 7));

    r = new CollectSupportDataArchiveFragmentIntermediateResponse(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.66");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getArchiveFileName());
    assertEquals(r.getArchiveFileName(), "csd.zip");

    assertEquals(r.getTotalArchiveSizeBytes(), 123_456L);

    assertTrue(r.moreDataToReturn());

    assertNotNull(r.getFragmentData());
    assertEquals(r.getFragmentData(),
         StaticUtils.byteArray(1, 2, 3, 4, 5, 6, 7));

    assertNotNull(r.getIntermediateResponseName());
    assertFalse(r.getIntermediateResponseName().isEmpty());

    assertNotNull(r.valueToString());
    assertFalse(r.valueToString().isEmpty());

    assertNotNull(r.toString());
    assertFalse(r.toString().isEmpty());
  }



  /**
   * Tests a valid instance of the intermediate response without any more data
   * to return and a single control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidResponseWithNoMoreToReturnOneControl()
         throws Exception
  {
    CollectSupportDataArchiveFragmentIntermediateResponse r =
         new CollectSupportDataArchiveFragmentIntermediateResponse("csd2.zip",
              987_654L, false, StaticUtils.byteArray(1, 2, 3, 4, 5),
              new Control("1.2.3.4"));

    r = new CollectSupportDataArchiveFragmentIntermediateResponse(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.66");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getArchiveFileName());
    assertEquals(r.getArchiveFileName(), "csd2.zip");

    assertEquals(r.getTotalArchiveSizeBytes(), 987_654L);

    assertFalse(r.moreDataToReturn());

    assertNotNull(r.getFragmentData());
    assertEquals(r.getFragmentData(),
         StaticUtils.byteArray(1, 2, 3, 4, 5));

    assertNotNull(r.getIntermediateResponseName());
    assertFalse(r.getIntermediateResponseName().isEmpty());

    assertNotNull(r.valueToString());
    assertFalse(r.valueToString().isEmpty());

    assertNotNull(r.toString());
    assertFalse(r.toString().isEmpty());
  }



  /**
   * Tests a valid instance of the intermediate response without any more data
   * to return and multiple controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidResponseWithNoMoreToReturnMultipleControls()
         throws Exception
  {
    CollectSupportDataArchiveFragmentIntermediateResponse r =
         new CollectSupportDataArchiveFragmentIntermediateResponse("csd3.zip",
              987_654L, false, StaticUtils.byteArray(1, 2, 3, 4, 5),
              new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new CollectSupportDataArchiveFragmentIntermediateResponse(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.66");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getArchiveFileName());
    assertEquals(r.getArchiveFileName(), "csd3.zip");

    assertEquals(r.getTotalArchiveSizeBytes(), 987_654L);

    assertFalse(r.moreDataToReturn());

    assertNotNull(r.getFragmentData());
    assertEquals(r.getFragmentData(),
         StaticUtils.byteArray(1, 2, 3, 4, 5));

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
    new CollectSupportDataArchiveFragmentIntermediateResponse(
         new IntermediateResponse("1.3.6.1.4.1.30221.2.6.66", null));
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
    new CollectSupportDataArchiveFragmentIntermediateResponse(
         new IntermediateResponse("1.3.6.1.4.1.30221.2.6.66",
              new ASN1OctetString("malformed")));
  }
}
