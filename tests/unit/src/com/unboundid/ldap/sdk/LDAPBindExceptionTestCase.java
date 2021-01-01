/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
 * This class provides test coverage for the {@code LDAPBindException} class.
 */
public final class LDAPBindExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the {@code LDAPBindException} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindException()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/ou=People,dc=example,dc=com",
      "ldap://ds2.example.com:389/ou=People,dc=example,dc=com"
    };

    final Control[] responseControls =
    {
      new Control("1.2.3.4"),
      new Control("5.6.7.8")
    };

    final BindResult bindResult = new BindResult(1234,
         ResultCode.INVALID_CREDENTIALS, "Wrong!",
         "ou=People,dc=example,dc=com", referralURLs, responseControls,
         new ASN1OctetString("Server SASL Credentials"));
    final LDAPBindException bindException = new LDAPBindException(bindResult);

    assertNotNull(bindException.getResultCode());
    assertEquals(bindException.getResultCode(), ResultCode.INVALID_CREDENTIALS);

    assertNotNull(bindException.getDiagnosticMessage());
    assertEquals(bindException.getDiagnosticMessage(), "Wrong!");

    assertNotNull(bindException.getMatchedDN());
    assertDNsEqual(bindException.getMatchedDN(), "ou=People,dc=example,dc=com");

    assertNotNull(bindException.getReferralURLs());
    assertEquals(bindException.getReferralURLs().length, 2);

    assertNotNull(bindException.getResponseControls());
    assertEquals(bindException.getResponseControls().length, 2);

    assertNotNull(bindException.toLDAPResult());
    assertTrue(bindException.toLDAPResult() instanceof BindResult);

    assertNotNull(bindException.getBindResult());
    assertTrue(bindException.getBindResult() instanceof BindResult);

    assertNotNull(bindException.getServerSASLCredentials());
    assertEquals(bindException.getServerSASLCredentials().stringValue(),
         "Server SASL Credentials");
  }
}
