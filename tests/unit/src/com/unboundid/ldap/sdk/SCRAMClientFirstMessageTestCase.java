/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the SCRAM client first message.
 */
public final class SCRAMClientFirstMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when creating a client first message with a randomly
   * generated nonce.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRandomNonce()
         throws Exception
  {
    final SCRAMSHA1BindRequest bindRequest =
         new SCRAMSHA1BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessaage =
         new SCRAMClientFirstMessage(bindRequest);

    assertNotNull(clientFirstMessaage.getBindRequest());

    assertNotNull(clientFirstMessaage.getGS2HeaderRaw());
    assertEquals(clientFirstMessaage.getGS2HeaderRaw(), "n,,");

    assertNotNull(clientFirstMessaage.getGS2HeaderBase64());
    assertEquals(clientFirstMessaage.getGS2HeaderBase64(), "biws");

    assertNotNull(clientFirstMessaage.getClientNonce());
    assertFalse(clientFirstMessaage.getClientNonce().isEmpty());

    assertNotNull(clientFirstMessaage.getClientFirstMessage());
    assertEquals(clientFirstMessaage.getClientFirstMessage(),
         "n,,n=user,r=" + clientFirstMessaage.getClientNonce());

    assertNotNull(clientFirstMessaage.getClientFirstMessageBare());
    assertEquals(clientFirstMessaage.getClientFirstMessageBare(),
         "n=user,r=" + clientFirstMessaage.getClientNonce());

    assertNotNull(clientFirstMessaage.toString());
    assertEquals(clientFirstMessaage.toString(),
         clientFirstMessaage.getClientFirstMessage());
  }



  /**
   * Tests the behavior when creating a client first message with a predefined
   * nonce for an SCRAM-SHA-1 bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPredefinedNonceSCRAMSHA1()
         throws Exception
  {
    final SCRAMSHA1BindRequest bindRequest =
         new SCRAMSHA1BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "fyko+d2lbbFgONRv9qkxdawL");

    assertNotNull(clientFirstMessage.getBindRequest());

    assertNotNull(clientFirstMessage.getGS2HeaderRaw());
    assertEquals(clientFirstMessage.getGS2HeaderRaw(), "n,,");

    assertNotNull(clientFirstMessage.getGS2HeaderBase64());
    assertEquals(clientFirstMessage.getGS2HeaderBase64(), "biws");

    assertNotNull(clientFirstMessage.getClientNonce());
    assertEquals(clientFirstMessage.getClientNonce(),
         "fyko+d2lbbFgONRv9qkxdawL");

    assertNotNull(clientFirstMessage.getClientFirstMessage());
    assertEquals(clientFirstMessage.getClientFirstMessage(),
         "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");

    assertNotNull(clientFirstMessage.getClientFirstMessageBare());
    assertEquals(clientFirstMessage.getClientFirstMessageBare(),
         "n=user,r=fyko+d2lbbFgONRv9qkxdawL");

    assertNotNull(clientFirstMessage.toString());
    assertEquals(clientFirstMessage.toString(),
         "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");
  }



  /**
   * Tests the behavior when creating a client first message with a predefined
   * nonce for an SCRAM-SHA-256 bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPredefinedNonceSCRAMSHA256()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    assertNotNull(clientFirstMessage.getBindRequest());

    assertNotNull(clientFirstMessage.getGS2HeaderRaw());
    assertEquals(clientFirstMessage.getGS2HeaderRaw(), "n,,");

    assertNotNull(clientFirstMessage.getGS2HeaderBase64());
    assertEquals(clientFirstMessage.getGS2HeaderBase64(), "biws");

    assertNotNull(clientFirstMessage.getClientNonce());
    assertEquals(clientFirstMessage.getClientNonce(), "rOprNGfwEbeRWgbNEkqO");

    assertNotNull(clientFirstMessage.getClientFirstMessage());
    assertEquals(clientFirstMessage.getClientFirstMessage(),
         "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");

    assertNotNull(clientFirstMessage.getClientFirstMessageBare());
    assertEquals(clientFirstMessage.getClientFirstMessageBare(),
         "n=user,r=rOprNGfwEbeRWgbNEkqO");

    assertNotNull(clientFirstMessage.toString());
    assertEquals(clientFirstMessage.toString(),
         "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
  }
}
