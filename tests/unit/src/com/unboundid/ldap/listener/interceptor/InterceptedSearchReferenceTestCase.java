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

import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides test coverage for the intercepted in-memory search
 * reference.
 */
public final class InterceptedSearchReferenceTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for an intercepted search reference.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasics()
         throws Exception
  {
    // Create an intercepted search reference.  We'll use a null connection,
    // which shouldn't happen naturally but will be sufficient for this test.
    final SearchRequestProtocolOp requestOp =
         new SearchRequestProtocolOp(new SearchRequest("dc=example,dc=com",
              SearchScope.BASE, "(objectClass=*)"));

    String[] referralURLs =
    {
      "ldap://ds1.example.com/"
    };
    final InterceptedSearchReference r = new InterceptedSearchReference(
         new InterceptedSearchOperation(null, 1, requestOp),
         new SearchResultReferenceProtocolOp(new SearchResultReference(1,
              referralURLs, null)));
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

    assertNotNull(r.getSearchReference());
    assertEquals(r.getSearchReference().getReferralURLs().length, 1);
    assertNotNull(r.toString());

    referralURLs = new String[]
    {
      "ldap://ds1.example.com/",
      "ldap://ds2.example.com/"
    };
    r.setSearchReference(new SearchResultReference(1, referralURLs, null));

    assertNotNull(r.getSearchReference());
    assertEquals(r.getSearchReference().getReferralURLs().length, 2);
    assertNotNull(r.toString());

    r.setSearchReference(null);
    assertNull(r.getSearchReference());
    assertNotNull(r.toString());
  }
}
