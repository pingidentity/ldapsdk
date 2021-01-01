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
package com.unboundid.util;



import java.util.Iterator;
import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the subtree deleter search
 * result listener class.
 */
public final class SubtreeDeleterSearchResultListenerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the listener when provided with search result
   * entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListenerWithEntries()
         throws Exception
  {
    final TreeSet<DN> dnSet = new TreeSet<>();

    final SubtreeDeleterSearchResultListener listener =
         new SubtreeDeleterSearchResultListener(new DN("dc=example,dc=com"),
              Filter.createPresenceFilter("objectClass"), dnSet);
    assertDNSetEquals(dnSet);
    assertNull(listener.getFirstException());

    listener.searchEntryReturned(new SearchResultEntry(new Entry(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People")));
    assertDNSetEquals(dnSet,
         "ou=People,dc=example,dc=com");
    assertNull(listener.getFirstException());

    listener.searchEntryReturned(new SearchResultEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example")));
    assertDNSetEquals(dnSet,
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com");
    assertNull(listener.getFirstException());

    listener.searchEntryReturned(new SearchResultEntry(new Entry(
         "dn: malformed,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: malformed")));
    assertDNSetEquals(dnSet,
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com");
    assertNotNull(listener.getFirstException());
  }



  /**
   * Provides test coverage for the listener when provided with a search result
   * reference with a single referral URL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListenerWithSingleURLReference()
         throws Exception
  {
    final TreeSet<DN> dnSet = new TreeSet<>();

    final SubtreeDeleterSearchResultListener listener =
         new SubtreeDeleterSearchResultListener(new DN("dc=example,dc=com"),
              Filter.createPresenceFilter("objectClass"), dnSet);
    assertDNSetEquals(dnSet);
    assertNull(listener.getFirstException());

    listener.searchReferenceReturned(new SearchResultReference(
         new String[]
         {
           "ldap://ds2.example,com:389/"
         },
         StaticUtils.NO_CONTROLS));
    assertDNSetEquals(dnSet);
    final LDAPException firstException = listener.getFirstException();
    assertNotNull(firstException);


    listener.searchReferenceReturned(new SearchResultReference(
         new String[]
         {
           "ldap://ds3.example,com:389/"
         },
         StaticUtils.NO_CONTROLS));
    assertDNSetEquals(dnSet);
    assertNotNull(listener.getFirstException());
    assertSame(listener.getFirstException(), firstException);
  }



  /**
   * Provides test coverage for the listener when provided with a search result
   * reference with multiple referral URLs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListenerWithMultiURLReference()
         throws Exception
  {
    final TreeSet<DN> dnSet = new TreeSet<>();

    final SubtreeDeleterSearchResultListener listener =
         new SubtreeDeleterSearchResultListener(new DN("dc=example,dc=com"),
              Filter.createPresenceFilter("objectClass"), dnSet);
    assertDNSetEquals(dnSet);
    assertNull(listener.getFirstException());

    listener.searchReferenceReturned(new SearchResultReference(
         new String[]
         {
           "ldap://ds2.example,com:389/",
           "ldap://ds3.example,com:389/"
         },
         StaticUtils.NO_CONTROLS));
    assertDNSetEquals(dnSet);
    final LDAPException firstException = listener.getFirstException();
    assertNotNull(firstException);


    listener.searchReferenceReturned(new SearchResultReference(
         new String[]
         {
           "ldap://ds4.example,com:389/",
           "ldap://ds5.example,com:389/"
         },
         StaticUtils.NO_CONTROLS));
    assertDNSetEquals(dnSet);
    assertNotNull(listener.getFirstException());
    assertSame(listener.getFirstException(), firstException);
  }



  /**
   * Ensures that the provided DN set contains the expected values.
   *
   * @param  dnSet        The set to examine.  It must not be {@code null}.
   * @param  expectedDNs  The string representations of the DNs expected to be
   *                      in the provided set, in the expected order.  It must
   *                      not be {@code null}, but may be empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void assertDNSetEquals(final TreeSet<DN> dnSet,
                                        final String... expectedDNs)
          throws Exception
  {
    assertEquals(dnSet.size(), expectedDNs.length);

    final Iterator<DN> iterator = dnSet.iterator();
    for (final String expectedDN : expectedDNs)
    {
      assertEquals(iterator.next(), new DN(expectedDN));
    }
  }
}
