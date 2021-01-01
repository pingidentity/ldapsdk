/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
 * This class provides a set of test cases for the SASL bind in progress
 * exception.
 */
public final class SASLBindInProgressExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the case in which the bind response includes
   * server SASL credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithServerSASLCredentials()
         throws Exception
  {
    final BindResult bindResult = new BindResult(1,
         ResultCode.SASL_BIND_IN_PROGRESS, null, null, null, null,
         new ASN1OctetString("server creds"));

    final SASLBindInProgressException e =
         new SASLBindInProgressException(bindResult);

    assertNotNull(e.getBindResult());

    assertNotNull(e.getServerSASLCredentials());
    assertEquals(e.getServerSASLCredentials().stringValue(), "server creds");

    assertNotNull(e.getMessage());

    assertEquals(e.getResultCode(), ResultCode.SASL_BIND_IN_PROGRESS);

    assertNull(e.getDiagnosticMessage());

    assertNull(e.getMatchedDN());

    assertNotNull(e.getReferralURLs());
    assertEquals(e.getReferralURLs().length, 0);
  }



  /**
   * Provides test coverage for the case in which the bind response does not
   * include server SASL credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutServerSASLCredentials()
         throws Exception
  {
    final BindResult bindResult = new BindResult(1,
         ResultCode.SASL_BIND_IN_PROGRESS, null, null, null, null, null);

    final SASLBindInProgressException e =
         new SASLBindInProgressException(bindResult);

    assertNotNull(e.getBindResult());

    assertNull(e.getServerSASLCredentials());

    assertNotNull(e.getMessage());

    assertEquals(e.getResultCode(), ResultCode.SASL_BIND_IN_PROGRESS);

    assertNull(e.getDiagnosticMessage());

    assertNull(e.getMatchedDN());

    assertNotNull(e.getReferralURLs());
    assertEquals(e.getReferralURLs().length, 0);
  }
}
