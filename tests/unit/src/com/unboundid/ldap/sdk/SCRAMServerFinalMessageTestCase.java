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
 * This class provides a set of test cases for the SCRAM server final message.
 */
public final class SCRAMServerFinalMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when creating a server final message for a
   * SCRAM-SHA-1 bind request with a successful bind that doesn't have any
   * extensions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSCRAMSHA1SuccessfulBindNoExtensions()
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

    final String serverFinalMessageString = "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFinalMessageString));

    final SCRAMServerFinalMessage serverFinalMessage =
         new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
              clientFinalMessage, serverFinalBindResult);

    assertNotNull(serverFinalMessage.getBindRequest());

    assertNotNull(serverFinalMessage.getClientFirstMessage());

    assertNotNull(serverFinalMessage.getClientFinalMessage());

    assertNotNull(serverFinalMessage.getServerSignatureBase64());
    assertEquals(serverFinalMessage.getServerSignatureBase64(),
         "rmF9pqV8S7suAoZWja4dJRkFsKQ=");

    assertNotNull(serverFinalMessage.getServerFinalMessage());
    assertEquals(serverFinalMessage.getServerFinalMessage(),
         "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");

    assertNotNull(serverFinalMessage.toString());
    assertEquals(serverFinalMessage.toString(),
         "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");
  }



  /**
   * Tests the behavior when creating a server first message for a
   * SCRAM-SHA-256 bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSCRAMSHA256SuccessfulBindNoExtensions()
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

    final String serverFinalMessageString =
         "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFinalMessageString));

    final SCRAMServerFinalMessage serverFinalMessage =
         new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
              clientFinalMessage, serverFinalBindResult);

    assertNotNull(serverFinalMessage.getBindRequest());

    assertNotNull(serverFinalMessage.getClientFirstMessage());

    assertNotNull(serverFinalMessage.getClientFinalMessage());

    assertNotNull(serverFinalMessage.getServerSignatureBase64());
    assertEquals(serverFinalMessage.getServerSignatureBase64(),
         "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");

    assertNotNull(serverFinalMessage.getServerFinalMessage());
    assertEquals(serverFinalMessage.getServerFinalMessage(),
         "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");

    assertNotNull(serverFinalMessage.toString());
    assertEquals(serverFinalMessage.toString(),
         "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
  }



  /**
   * Tests the behavior when creating a server final message for a
   * SCRAM-SHA-1 bind request with a successful bind that includes extensions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSCRAMSHA1SuccessfulBindWithExtensions()
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

    final String serverFinalMessageString =
         "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=,foo=bar,abc=123";

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFinalMessageString));

    final SCRAMServerFinalMessage serverFinalMessage =
         new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
              clientFinalMessage, serverFinalBindResult);

    assertNotNull(serverFinalMessage.getBindRequest());

    assertNotNull(serverFinalMessage.getClientFirstMessage());

    assertNotNull(serverFinalMessage.getClientFinalMessage());

    assertNotNull(serverFinalMessage.getServerSignatureBase64());
    assertEquals(serverFinalMessage.getServerSignatureBase64(),
         "rmF9pqV8S7suAoZWja4dJRkFsKQ=");

    assertNotNull(serverFinalMessage.getServerFinalMessage());
    assertEquals(serverFinalMessage.getServerFinalMessage(),
         "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=,foo=bar,abc=123");

    assertNotNull(serverFinalMessage.toString());
    assertEquals(serverFinalMessage.toString(),
         "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=,foo=bar,abc=123");
  }



  /**
   * Tests the behavior when creating a server final message for a
   * SCRAM-SHA-1 bind request with a non-successful bind that does not include
   * any SASL credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testSCRAMSHA1NonSuccessfulBindNoCredentials()
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

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.INVALID_CREDENTIALS, null, null, null, null, null);

    new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
         clientFinalMessage, serverFinalBindResult);
  }



  /**
   * Tests the behavior when creating a server final message for a
   * SCRAM-SHA-1 bind request with a non-successful bind that has valid error
   * credentials and no extensions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testSCRAMSHA1NonSuccessfulBindWithErrorCredentialsNoExtensions()
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

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.INVALID_CREDENTIALS, null, null, null, null,
         new ASN1OctetString("e=invalid-proof"));

    new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
         clientFinalMessage, serverFinalBindResult);
  }



  /**
   * Tests the behavior when creating a server final message for a
   * SCRAM-SHA-1 bind request with a non-successful bind that has valid error
   * credentials and also includes extensions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testSCRAMSHA1NonSuccessfulBindWithErrorCredentialsWithExtensions()
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

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.INVALID_CREDENTIALS, "This is the diagnostic message", null,
         null, null, new ASN1OctetString("e=invalid-proof,foo=bar,abc=123"));

    new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
         clientFinalMessage, serverFinalBindResult);
  }



  /**
   * Tests the behavior when creating a server final message for a
   * SCRAM-SHA-1 bind request with a non-successful bind that has some other
   * unexpected type of credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testSCRAMSHA1NonSuccessfulBindWithErrorCredentials()
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

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.INVALID_CREDENTIALS, null, null, null, null,
         new ASN1OctetString("some unexpected form of credentials"));

    new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
         clientFinalMessage, serverFinalBindResult);
  }



  /**
   * Tests the behavior when creating a server final message for a
   * SCRAM-SHA-1 bind request with a successful bind that has an invalid
   * signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testSCRAMSHA1SuccessfulBindInvalidSignature()
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

    final String serverFinalMessageString = "v=InvalidSignature";

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFinalMessageString));

    new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
         clientFinalMessage, serverFinalBindResult);
  }



  /**
   * Tests the behavior when creating a server first message for a
   * SCRAM-SHA-256 bind request with a successful bind that has an invalid
   * signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testSCRAMSHA256SuccessfulInvalidSignature()
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

    final String serverFinalMessageString = "v=InvalidSignature";

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString(serverFinalMessageString));

    new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
         clientFinalMessage, serverFinalBindResult);
  }



  /**
   * Tests the behavior when creating a server first message for a successful
   * bind that does not include server SASL credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testSCRAMSHA256SuccessfulNoCredentials()
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

    final String serverFinalMessageString = "v=InvalidSignature";

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.SUCCESS, null, null, null, null, null);

    new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
         clientFinalMessage, serverFinalBindResult);
  }



  /**
   * Tests the behavior when creating a server final message for a
   * SCRAM-SHA-1 bind request with a successful bind that has some other
   * unexpected type of credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testSCRAMSHA1SuccessfulBindWithErrorCredentials()
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

    final BindResult serverFinalBindResult = new BindResult(2,
         ResultCode.SUCCESS, null, null, null, null,
         new ASN1OctetString("some unexpected form of credentials"));

    new SCRAMServerFinalMessage(bindRequest, clientFirstMessage,
         clientFinalMessage, serverFinalBindResult);
  }
}
