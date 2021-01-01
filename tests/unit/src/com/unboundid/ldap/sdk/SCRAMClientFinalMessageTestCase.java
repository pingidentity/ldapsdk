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

import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides a set of test cases for the SCRAM client final message.
 */
public final class SCRAMClientFinalMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when creating a client final message for a
   * SCRAM-SHA-1 bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSCRAMSHA1()
         throws Exception
  {
    final SCRAMSHA1BindRequest bindRequest =
         new SCRAMSHA1BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "fyko+d2lbbFgONRv9qkxdawL");

    final String serverFirstMessageString =
         "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92," +
              "i=4096";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    final SCRAMServerFirstMessage serverFirstMessage =
         new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
              serverFirstBindResult);

    final SCRAMClientFinalMessage clientFinalMessage =
         new SCRAMClientFinalMessage(bindRequest, clientFirstMessage,
              serverFirstMessage);

    assertNotNull(clientFinalMessage.getBindRequest());

    assertNotNull(clientFinalMessage.getClientFirstMessage());

    assertNotNull(clientFinalMessage.getServerFirstMessage());

    assertNotNull(clientFinalMessage.getSaltedPassword());

    assertNotNull(clientFinalMessage.getAuthMessageBytes());

    assertNotNull(clientFinalMessage.getClientProofBase64());
    assertEquals(clientFinalMessage.getClientProofBase64(),
         "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");

    assertNotNull(clientFinalMessage.getClientFinalMessage());
    assertEquals(clientFinalMessage.getClientFinalMessage(),
         "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j," +
              "p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");

    assertNotNull(clientFinalMessage.toString());
    assertEquals(clientFinalMessage.toString(),
         "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j," +
              "p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
  }



  /**
   * Tests the behavior when creating a server first message for a
   * SCRAM-SHA-256 bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSCRAMSHA256()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
              "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    final SCRAMServerFirstMessage serverFirstMessage =
         new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
              serverFirstBindResult);

    final SCRAMClientFinalMessage clientFinalMessage =
         new SCRAMClientFinalMessage(bindRequest, clientFirstMessage,
              serverFirstMessage);

    assertNotNull(clientFinalMessage.getBindRequest());

    assertNotNull(clientFinalMessage.getClientFirstMessage());

    assertNotNull(clientFinalMessage.getServerFirstMessage());

    assertNotNull(clientFinalMessage.getSaltedPassword());

    assertNotNull(clientFinalMessage.getAuthMessageBytes());

    assertNotNull(clientFinalMessage.getClientProofBase64());
    assertEquals(clientFinalMessage.getClientProofBase64(),
         "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");

    assertNotNull(clientFinalMessage.getClientFinalMessage());
    assertEquals(clientFinalMessage.getClientFinalMessage(),
         "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
              "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");

    assertNotNull(clientFinalMessage.toString());
    assertEquals(clientFinalMessage.toString(),
         "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
              "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
  }
}
