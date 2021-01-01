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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code ChangelogBatchStartingPoint} class.
 */
public final class ChangelogBatchStartingPointTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the ability to decode an instance of a resume
   * with token starting point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeResumeWithTokenStartingPoint()
         throws Exception
  {
    final ASN1OctetString token = new ASN1OctetString("foo");
    final ResumeWithTokenStartingPoint sp =
         new ResumeWithTokenStartingPoint(token);

    final ASN1Element e = sp.encode();
    assertNotNull(e);

    final ChangelogBatchStartingPoint genericSP =
         ChangelogBatchStartingPoint.decode(e);
    assertTrue(genericSP instanceof ResumeWithTokenStartingPoint);

    final ResumeWithTokenStartingPoint decodedSP =
         (ResumeWithTokenStartingPoint) genericSP;
    assertTrue(Arrays.equals(decodedSP.getResumeToken().getValue(),
         token.getValue()));
  }



  /**
   * Provides test coverage for the ability to decode an instance of a resume
   * with CSN starting point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeResumeWithCSNStartingPoint()
         throws Exception
  {
    final String csn = "12345";
    final ResumeWithCSNStartingPoint sp = new ResumeWithCSNStartingPoint(csn);

    final ASN1Element e = sp.encode();
    assertNotNull(e);

    final ChangelogBatchStartingPoint genericSP =
         ChangelogBatchStartingPoint.decode(e);
    assertTrue(genericSP instanceof ResumeWithCSNStartingPoint);

    final ResumeWithCSNStartingPoint decodedSP =
         (ResumeWithCSNStartingPoint) genericSP;
    assertEquals(decodedSP.getCSN(), csn);
  }



  /**
   * Provides test coverage for the ability to decode an instance of a beginning
   * of changelog starting point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeBeginningOfChangelogStartingPoint()
         throws Exception
  {
    final BeginningOfChangelogStartingPoint sp =
         new BeginningOfChangelogStartingPoint();

    final ASN1Element e = sp.encode();
    assertNotNull(e);

    final ChangelogBatchStartingPoint genericSP =
         ChangelogBatchStartingPoint.decode(e);
    assertTrue(genericSP instanceof BeginningOfChangelogStartingPoint);
  }



  /**
   * Provides test coverage for the ability to decode a malformed instance of a
   * beginning of changelog starting point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedBeginningOfChangelogStartingPoint()
         throws Exception
  {
    ChangelogBatchStartingPoint.decode(new ASN1Element(
         BeginningOfChangelogStartingPoint.TYPE, new byte[] { 0x00 }));
  }



  /**
   * Provides test coverage for the ability to decode an instance of an end of
   * changelog starting point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEndOfChangelogStartingPoint()
         throws Exception
  {
    final EndOfChangelogStartingPoint sp = new EndOfChangelogStartingPoint();

    final ASN1Element e = sp.encode();
    assertNotNull(e);

    final ChangelogBatchStartingPoint genericSP =
         ChangelogBatchStartingPoint.decode(e);
    assertTrue(genericSP instanceof EndOfChangelogStartingPoint);
  }



  /**
   * Provides test coverage for the ability to decode a malformed instance of an
   * end of changelog starting point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedEndOfChangelogStartingPoint()
         throws Exception
  {
    ChangelogBatchStartingPoint.decode(new ASN1Element(
         EndOfChangelogStartingPoint.TYPE, new byte[] { 0x00 }));
  }



  /**
   * Provides test coverage for the ability to decode an instance of a change
   * time starting point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeChangeTimeStartingPoint()
         throws Exception
  {
    final long time = System.currentTimeMillis();
    final ChangeTimeStartingPoint sp = new ChangeTimeStartingPoint(time);

    final ASN1Element e = sp.encode();
    assertNotNull(e);

    final ChangelogBatchStartingPoint genericSP =
         ChangelogBatchStartingPoint.decode(e);
    assertTrue(genericSP instanceof ChangeTimeStartingPoint);

    final ChangeTimeStartingPoint decodedSP =
         (ChangeTimeStartingPoint) genericSP;
    assertEquals(decodedSP.getChangeTime(), time);
  }



  /**
   * Provides test coverage for the ability to decode a malformed instance of a
   * change time starting point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedChangeTimeStartingPoint()
         throws Exception
  {
    ChangelogBatchStartingPoint.decode(new ASN1Element(
         ChangeTimeStartingPoint.TYPE, new byte[] { 0x00 }));
  }



  /**
   * Provides test coverage for the attempt to decode a starting point with an
   * unexpected type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeUnexpectedStartingPointType()
         throws Exception
  {
    ChangelogBatchStartingPoint.decode(new ASN1Element((byte) 0x00));
  }
}
