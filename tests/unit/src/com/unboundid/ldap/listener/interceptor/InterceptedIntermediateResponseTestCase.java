/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener.interceptor;



import org.testng.annotations.Test;

import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.IntermediateResponseProtocolOp;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the intercepted in-memory intermediate
 * response.
 */
public final class InterceptedIntermediateResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for an intercepted intermediate response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasics()
         throws Exception
  {
    // Create an intercepted intermediate response.  We'll use a null
    // connection, which shouldn't happen naturally but will be sufficient for
    // this test.
    final AddRequestProtocolOp requestOp =
         new AddRequestProtocolOp(new AddRequest(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    final InterceptedAddOperation o = new InterceptedAddOperation(
         null, 1, requestOp);
    assertNotNull(o.toString());

    final IntermediateResponseProtocolOp responseOp =
         new IntermediateResponseProtocolOp(new IntermediateResponse(
              "1.2.3.4", null));

    final InterceptedIntermediateResponse r =
         new InterceptedIntermediateResponse(o, responseOp);
    assertNotNull(r.toString());


    // Test methods for a generic intercepted operation.
    assertNull(r.getClientConnection());

    assertEquals(r.getConnectionID(), -1L);

    assertNull(r.getConnectedAddress());

    assertEquals(r.getConnectedPort(), -1);

    assertEquals(r.getMessageID(), 1);

    assertNull(r.getProperty("propX"));

    r.setProperty("propX", "valX");
    assertNotNull(r.getProperty("propX"));
    assertEquals(r.getProperty("propX"), "valX");
    assertNotNull(r.toString());

    r.setProperty("propX", null);
    assertNull(r.getProperty("propX"));


    // Test methods specific to an intercepted compare operation.
    assertNotNull(r.getRequest());

    assertNotNull(r.getIntermediateResponse());
    assertEquals(r.getIntermediateResponse().getOID(), "1.2.3.4");
    assertNotNull(r.toString());

    r.setIntermediateResponse(new IntermediateResponse("5.6.7.8", null));
    assertEquals(r.getIntermediateResponse().getOID(), "5.6.7.8");
    assertNotNull(r.toString());

    r.setIntermediateResponse(null);
    assertNull(r.getIntermediateResponse());
    assertNotNull(r.toString());
  }
}
