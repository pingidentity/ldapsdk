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
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides test coverage for the intercepted in-memory search entry.
 */
public final class InterceptedSearchEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for an intercepted search entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasics()
         throws Exception
  {
    // Create an intercepted search entry.  We'll use a null connection, which
    // shouldn't happen naturally but will be sufficient for this test.
    final SearchRequestProtocolOp requestOp =
         new SearchRequestProtocolOp(new SearchRequest("dc=example,dc=com",
              SearchScope.BASE, "(objectClass=*)"));

    final InterceptedSearchEntry e = new InterceptedSearchEntry(
         new InterceptedSearchOperation(null, 1, requestOp),
         new SearchResultEntryProtocolOp(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));
    assertNotNull(e.toString());


    // Test methods for a generic intercepted operation.
    assertNull(e.getClientConnection());

    assertEquals(e.getConnectionID(), -1L);

    assertNull(e.getConnectedAddress());

    assertEquals(e.getConnectedPort(), -1);

    assertEquals(e.getMessageID(), 1);

    assertNull(e.getProperty("propX"));

    e.setProperty("propX", "valX");
    assertNotNull(e.getProperty("propX"));
    assertEquals(e.getProperty("propX"), "valX");
    assertNotNull(e.toString());

    e.setProperty("propX", null);
    assertNull(e.getProperty("propX"));


    // Test methods specific to an intercepted compare operation.
    assertNotNull(e.getRequest());

    assertNotNull(e.getSearchEntry());
    assertFalse(e.getSearchEntry().hasAttribute("description"));
    assertNotNull(e.getSearchEntry().getControls());
    assertEquals(e.getSearchEntry().getControls().length, 0);
    assertNotNull(e.toString());

    e.setSearchEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo"));

    assertNotNull(e.getSearchEntry());
    assertTrue(e.getSearchEntry().hasAttributeValue("description", "foo"));
    assertNotNull(e.getSearchEntry().getControls());
    assertEquals(e.getSearchEntry().getControls().length, 0);
    assertNotNull(e.toString());

    e.setSearchEntry(new SearchResultEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: bar"),
         new Control("1.2.3.4"), new Control("1.2.3.5")));

    assertNotNull(e.getSearchEntry());
    assertTrue(e.getSearchEntry().hasAttributeValue("description", "bar"));
    assertNotNull(e.getSearchEntry().getControls());
    assertEquals(e.getSearchEntry().getControls().length, 2);
    assertNotNull(e.toString());

    e.setSearchEntry(null);
    assertNull(e.getSearchEntry());
  }
}
