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
 * This class provides a set of test cases for the tool-default log capture
 * window.
 */
public final class ToolDefaultCollectSupportDataLogCaptureWindowTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the log capture window.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogCaptureWindow()
         throws Exception
  {
    ToolDefaultCollectSupportDataLogCaptureWindow lcw =
         ToolDefaultCollectSupportDataLogCaptureWindow.getInstance();
    assertNotNull(lcw);

    lcw = ToolDefaultCollectSupportDataLogCaptureWindow.decodeInternal(
         lcw.encode());
    assertNotNull(lcw);

    assertNotNull(lcw.toString());
  }



  /**
   * Tests the behavior when trying to decode a log capture window from a
   * malformed element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformed()
         throws Exception
  {
    ToolDefaultCollectSupportDataLogCaptureWindow.decodeInternal(
         new ASN1OctetString((byte) 0x80, "malformed"));
  }
}
