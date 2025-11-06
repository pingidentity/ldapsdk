/*
 * Copyright 2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2025 Ping Identity Corporation
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
 * Copyright (C) 2025 Ping Identity Corporation
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

import com.unboundid.ldap.listener.InMemoryDirectoryServer;



/**
 * This class provides a set of tests to verify the functionality of the
 * discard results search result listener.
 */
public final class DiscardResultsSearchResultListenerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Ensures that the listener methods are invoked and return without issue.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListenerMethods()
         throws Exception
  {
    final DiscardResultsSearchResultListener listener =
         DiscardResultsSearchResultListener.getInstance();
    assertNotNull(listener);

    listener.searchEntryReturned(new SearchResultEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example")));

    listener.searchReferenceReturned(new SearchResultReference(
         new String[]
         {
           "ldap://ds.example.com/"
         },
         null));
  }



  /**
   * Tests the listener with a search operation in a case where the server
   * should return ten entries and two references.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchOperation()
         throws Exception
  {
    // Populate a server instance with some test data.
    final InMemoryDirectoryServer ds = getTestDS(false, false);

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    for (int i=0; i < 10; i++)
    {
      ds.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);
    }

    for (int i=0; i < 2; i++)
    {
      ds.add(
           "dn: ou=ref " + i + ",dc=example,dc=com",
           "objectClass: top",
           "objectClass: referral",
           "objectClass: extensibleObject",
           "ou: ref " + i,
           "ref: ldap:///ou=People,dc=example,dc=com");
    }


    // Issue a search request using the listener.  Ensure that the search
    // completes successfully and that we can retrieve the number of entries
    // and references returned but not their contents.
    final SearchRequest searchRequest = new SearchRequest(
         DiscardResultsSearchResultListener.getInstance(), "dc=example,dc=com",
         SearchScope.SUB, Filter.equals("objectClass", "person"), "1.1");

    try (LDAPConnection conn = ds.getConnection())
    {
      final SearchResult searchResult = (SearchResult)
           assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);

      assertEquals(searchResult.getEntryCount(), 10);
      assertNull(searchResult.getSearchEntries());

      assertEquals(searchResult.getReferenceCount(), 2);
      assertNull(searchResult.getSearchReferences());
    }
  }
}
