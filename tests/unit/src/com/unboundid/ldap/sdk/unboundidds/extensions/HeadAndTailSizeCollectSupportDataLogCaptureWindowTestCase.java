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

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the head and tail size log
 * capture window.
 */
public final class HeadAndTailSizeCollectSupportDataLogCaptureWindowTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a log capture window that specifies values for both
   * properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBothValues()
         throws Exception
  {
    HeadAndTailSizeCollectSupportDataLogCaptureWindow lcw =
         new HeadAndTailSizeCollectSupportDataLogCaptureWindow(123, 456);

    lcw = HeadAndTailSizeCollectSupportDataLogCaptureWindow.decodeInternal(
         lcw.encode());

    assertNotNull(lcw.getHeadSizeKB());
    assertEquals(lcw.getHeadSizeKB().intValue(), 123);

    assertNotNull(lcw.getTailSizeKB());
    assertEquals(lcw.getTailSizeKB().intValue(), 456);

    assertNotNull(lcw.toString());
  }



  /**
   * Tests the behavior for a log capture window that specifies values for the
   * head size but not the tail size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHeadWithoutTail()
         throws Exception
  {
    HeadAndTailSizeCollectSupportDataLogCaptureWindow lcw =
         new HeadAndTailSizeCollectSupportDataLogCaptureWindow(789, null);

    lcw = HeadAndTailSizeCollectSupportDataLogCaptureWindow.decodeInternal(
         lcw.encode());

    assertNotNull(lcw.getHeadSizeKB());
    assertEquals(lcw.getHeadSizeKB().intValue(), 789);

    assertNull(lcw.getTailSizeKB());

    assertNotNull(lcw.toString());
  }



  /**
   * Tests the behavior for a log capture window that specifies values for the
   * tail size but not the head size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTailWithoutHead()
         throws Exception
  {
    HeadAndTailSizeCollectSupportDataLogCaptureWindow lcw =
         new HeadAndTailSizeCollectSupportDataLogCaptureWindow(null, 987);

    lcw = HeadAndTailSizeCollectSupportDataLogCaptureWindow.decodeInternal(
         lcw.encode());

    assertNull(lcw.getHeadSizeKB());

    assertNotNull(lcw.getTailSizeKB());
    assertEquals(lcw.getTailSizeKB().intValue(), 987);

    assertNotNull(lcw.toString());
  }



  /**
   * Tests the behavior for a log capture window that does not specify a value
   * for either property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNeitherValue()
         throws Exception
  {
    HeadAndTailSizeCollectSupportDataLogCaptureWindow lcw =
         new HeadAndTailSizeCollectSupportDataLogCaptureWindow(null, null);

    lcw = HeadAndTailSizeCollectSupportDataLogCaptureWindow.decodeInternal(
         lcw.encode());

    assertNull(lcw.getHeadSizeKB());

    assertNull(lcw.getTailSizeKB());

    assertNotNull(lcw.toString());
  }



  /**
   * Tests the behavior when trying to create a window with a negative head
   * size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNegativeHeadSize()
         throws Exception
  {
    new HeadAndTailSizeCollectSupportDataLogCaptureWindow(-1, null);
  }



  /**
   * Tests the behavior when trying to create a window with a negative tail
   * size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNegativeTailSize()
         throws Exception
  {
    new HeadAndTailSizeCollectSupportDataLogCaptureWindow(null, -1);
  }



  /**
   * Tests the behavior when trying to decode a malformed element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedElement()
         throws Exception
  {
    HeadAndTailSizeCollectSupportDataLogCaptureWindow.decodeInternal(
         new ASN1OctetString("malformed"));
  }



  /**
   * Tests the behavior when trying to decode an element that has a negative
   * head size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNegativeHeadSize()
         throws Exception
  {
    HeadAndTailSizeCollectSupportDataLogCaptureWindow.decodeInternal(
         new ASN1Sequence(
              new ASN1Integer((byte) 0x80, -1)));
  }



  /**
   * Tests the behavior when trying to decode an element that has a negative
   * tail size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNegativeTailSize()
         throws Exception
  {
    HeadAndTailSizeCollectSupportDataLogCaptureWindow.decodeInternal(
         new ASN1Sequence(
              new ASN1Integer((byte) 0x81, -1)));
  }



  /**
   * Tests the behavior when trying to decode an element with an unexpected BER
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeUnexpectedElementType()
         throws Exception
  {
    HeadAndTailSizeCollectSupportDataLogCaptureWindow.decodeInternal(
         new ASN1Sequence(
              new ASN1Integer((byte) 0x82, 1)));
  }
}
