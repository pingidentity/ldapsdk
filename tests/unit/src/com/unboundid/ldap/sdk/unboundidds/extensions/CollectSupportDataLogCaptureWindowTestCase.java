/*
 * Copyright 2020-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2025 Ping Identity Corporation
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
 * Copyright (C) 2020-2025 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the collect support data log
 * capture window class.
 */
public final class CollectSupportDataLogCaptureWindowTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to decode a tool-default window instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeToolDefaultWindow()
         throws Exception
  {
    final CollectSupportDataLogCaptureWindow w =
         CollectSupportDataLogCaptureWindow.decode(
              ToolDefaultCollectSupportDataLogCaptureWindow.getInstance().
                   encode());

    assertNotNull(w);

    assertTrue(w instanceof  ToolDefaultCollectSupportDataLogCaptureWindow);

    assertNotNull(w.toString());
  }



  /**
   * Tests the behavior when trying to decode a duration log capture window.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeDurationWindow()
         throws Exception
  {
    final CollectSupportDataLogCaptureWindow w =
         CollectSupportDataLogCaptureWindow.decode(
              new DurationCollectSupportDataLogCaptureWindow(12345L).encode());

    assertNotNull(w);

    assertTrue(w instanceof  DurationCollectSupportDataLogCaptureWindow);

    assertNotNull(w.toString());
  }



  /**
   * Tests the behavior when trying to decode a time window log capture window.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeTimeWindow()
         throws Exception
  {
    final CollectSupportDataLogCaptureWindow w =
         CollectSupportDataLogCaptureWindow.decode(
              new TimeWindowCollectSupportDataLogCaptureWindow(
                   System.currentTimeMillis() - 600_000L,
                   System.currentTimeMillis()).encode());

    assertNotNull(w);

    assertTrue(w instanceof  TimeWindowCollectSupportDataLogCaptureWindow);

    assertNotNull(w.toString());
  }



  /**
   * Tests the behavior when trying to decode a head and tail size log capture
   * window.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeHeadAndTailSize()
         throws Exception
  {
    final CollectSupportDataLogCaptureWindow w =
         CollectSupportDataLogCaptureWindow.decode(
              new HeadAndTailSizeCollectSupportDataLogCaptureWindow(123,
                   456).encode());

    assertNotNull(w);

    assertTrue(w instanceof  HeadAndTailSizeCollectSupportDataLogCaptureWindow);

    assertNotNull(w.toString());
  }



  /**
   * Tests the behavior when trying to decode a malformed element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testMalformedElement()
         throws Exception
  {
    CollectSupportDataLogCaptureWindow.decode(
         new ASN1OctetString((byte) 8F, "malformed"));
  }
}
