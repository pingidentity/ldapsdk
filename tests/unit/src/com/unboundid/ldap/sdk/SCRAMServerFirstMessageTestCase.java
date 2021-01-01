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
import com.unboundid.util.Base64;



/**
 * This class provides a set of test cases for the SCRAM server first message.
 */
public final class SCRAMServerFirstMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when creating a server first message for a
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

    assertNotNull(serverFirstMessage.getBindRequest());

    assertNotNull(serverFirstMessage.getClientFirstMessage());

    assertNotNull(serverFirstMessage.getBindResult());

    assertNotNull(serverFirstMessage.getCombinedNonce());
    assertEquals(serverFirstMessage.getCombinedNonce(),
         "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j");

    assertNotNull(serverFirstMessage.getServerNonce());
    assertEquals(serverFirstMessage.getServerNonce(),
         "3rfcNHYJY1ZVvWVs7j");

    assertNotNull(serverFirstMessage.getSalt());
    assertEquals(serverFirstMessage.getSalt(),
         Base64.decode("QSXCR+Q6sek8bf92"));

    assertEquals(serverFirstMessage.getIterationCount(), 4096);

    assertNotNull(serverFirstMessage.getServerFirstMessage());
    assertEquals(serverFirstMessage.getServerFirstMessage(),
         serverFirstMessageString);

    assertNotNull(serverFirstMessage.toString());
    assertEquals(serverFirstMessage.toString(),
         serverFirstMessageString);
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

    assertNotNull(serverFirstMessage.getBindRequest());

    assertNotNull(serverFirstMessage.getClientFirstMessage());

    assertNotNull(serverFirstMessage.getBindResult());

    assertNotNull(serverFirstMessage.getCombinedNonce());
    assertEquals(serverFirstMessage.getCombinedNonce(),
         "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0");

    assertNotNull(serverFirstMessage.getServerNonce());
    assertEquals(serverFirstMessage.getServerNonce(),
         "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0");

    assertNotNull(serverFirstMessage.getSalt());
    assertEquals(serverFirstMessage.getSalt(),
         Base64.decode("W22ZaJ0SNY7soEsUEjb6gQ=="));

    assertEquals(serverFirstMessage.getIterationCount(), 4096);

    assertNotNull(serverFirstMessage.getServerFirstMessage());
    assertEquals(serverFirstMessage.getServerFirstMessage(),
         serverFirstMessageString);

    assertNotNull(serverFirstMessage.toString());
    assertEquals(serverFirstMessage.toString(),
         serverFirstMessageString);
  }



  /**
   * Tests the behavior when creating a server first message for a
   * SCRAM-SHA-256 bind request that has extensions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSCRAMSHA256WithExtensions()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
              "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,foo=bar,abc=123";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    final SCRAMServerFirstMessage serverFirstMessage =
         new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
              serverFirstBindResult);

    assertNotNull(serverFirstMessage.getBindRequest());

    assertNotNull(serverFirstMessage.getClientFirstMessage());

    assertNotNull(serverFirstMessage.getBindResult());

    assertNotNull(serverFirstMessage.getCombinedNonce());
    assertEquals(serverFirstMessage.getCombinedNonce(),
         "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0");

    assertNotNull(serverFirstMessage.getServerNonce());
    assertEquals(serverFirstMessage.getServerNonce(),
         "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0");

    assertNotNull(serverFirstMessage.getSalt());
    assertEquals(serverFirstMessage.getSalt(),
         Base64.decode("W22ZaJ0SNY7soEsUEjb6gQ=="));

    assertEquals(serverFirstMessage.getIterationCount(), 4096);

    assertNotNull(serverFirstMessage.getServerFirstMessage());
    assertEquals(serverFirstMessage.getServerFirstMessage(),
         serverFirstMessageString);

    assertNotNull(serverFirstMessage.toString());
    assertEquals(serverFirstMessage.toString(),
         serverFirstMessageString);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response without server SASL credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testNoServerSASLCredentials()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null, null);

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response with a message that does not start with a nonce.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testCredentialsDoesNotStartWithNonce()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString = "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response with a message that has an empty nonce.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testCredentialsEmptyNonce()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response with a message whose combined nonce does not start with the client
   * nonce.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testCredentialsCombinedNonceMissingClientNonce()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response with a message whose combined nonce matches the client nonce (and
   * does not include any additional server nonce).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testCredentialsCombinedNonceMissingServerNonce()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response with a message that does not include a salt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testCredentialsNoSalt()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,i=4096";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response with a message that has an empty salt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testCredentialsEmptySalt()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=,i=4096";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response with a message whose salt is not valid base 64.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testCredentialsSaltNotBase64()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
              "s=not~valid~base64,i=4096";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response with a message that does not include an iteration count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testCredentialsNoIterationCount()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
              "s=W22ZaJ0SNY7soEsUEjb6gQ==";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response with a message in which the iteration count cannot be parsed as a
   * string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testCredentialsIterationCountNotInteger()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
              "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=NotAnInteger";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }



  /**
   * Tests the behavior when trying to create a server first message from a bind
   * response with a message in which the iteration count is below the minimum
   * acceptable value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testCredentialsIterationCountTooSmall()
         throws Exception
  {
    final SCRAMSHA256BindRequest bindRequest =
         new SCRAMSHA256BindRequest("user", "pencil");

    final SCRAMClientFirstMessage clientFirstMessage =
         new SCRAMClientFirstMessage(bindRequest, "rOprNGfwEbeRWgbNEkqO");

    final String serverFirstMessageString =
         "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
              "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1234";

    final BindResult serverFirstBindResult = new BindResult(1,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFirstMessageString));

    new SCRAMServerFirstMessage(bindRequest, clientFirstMessage,
         serverFirstBindResult);
  }
}
