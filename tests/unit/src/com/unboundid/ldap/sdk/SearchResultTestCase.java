/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.util.ArrayList;

import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the SearchResult class.
 */
public class SearchResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor by simulating a successful search.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Successful()
         throws Exception
  {
    SearchResult searchResult =
         new SearchResult(1, ResultCode.SUCCESS, null, null, null, 10, 1, null);

    assertEquals(searchResult.getMessageID(), 1);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(searchResult.getDiagnosticMessage());

    assertNull(searchResult.getMatchedDN());

    assertNotNull(searchResult.getReferralURLs());
    assertEquals(searchResult.getReferralURLs().length, 0);

    assertEquals(searchResult.getEntryCount(), 10);

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNull(searchResult.getSearchEntries());

    assertNull(searchResult.getSearchEntry("dc=example,dc=com"));

    assertNull(searchResult.getSearchReferences());

    assertNotNull(searchResult.getResponseControls());
    assertEquals(searchResult.getResponseControls().length, 0);

    assertNotNull(searchResult.toString());
  }



  /**
   * Tests the first constructor by simulating a failed search.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Failed()
         throws Exception
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResult searchResult =
         new SearchResult(1, ResultCode.NO_SUCH_OBJECT,
                          "The specified entry does not exist.",
                          "dc=example,dc=com", referralURLs, 0, 0, controls);

    assertEquals(searchResult.getMessageID(), 1);

    assertEquals(searchResult.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(searchResult.getDiagnosticMessage());
    assertEquals(searchResult.getDiagnosticMessage(),
                 "The specified entry does not exist.");

    assertNotNull(searchResult.getMatchedDN());
    assertEquals(searchResult.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(searchResult.getReferralURLs());
    assertEquals(searchResult.getReferralURLs().length, 2);

    assertEquals(searchResult.getEntryCount(), 0);

    assertEquals(searchResult.getReferenceCount(), 0);

    assertNull(searchResult.getSearchEntries());

    assertNull(searchResult.getSearchEntry("dc=example,dc=com"));

    assertNull(searchResult.getSearchReferences());

    assertNotNull(searchResult.getResponseControls());
    assertEquals(searchResult.getResponseControls().length, 2);

    assertNotNull(searchResult.toString());
  }



  /**
   * Tests the second constructor by simulating a successful search with
   * entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SuccessfulWithEntries()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ArrayList<SearchResultEntry> entryList =
         new ArrayList<SearchResultEntry>(1);
    entryList.add(new SearchResultEntry("dc=example,dc=com", attrs, controls));

    SearchResult searchResult =
         new SearchResult(1, ResultCode.SUCCESS, null, null, null, entryList,
                          new ArrayList<SearchResultReference>(0), 1, 0, null);

    assertEquals(searchResult.getMessageID(), 1);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(searchResult.getDiagnosticMessage());

    assertNull(searchResult.getMatchedDN());

    assertNotNull(searchResult.getReferralURLs());
    assertEquals(searchResult.getReferralURLs().length, 0);

    assertEquals(searchResult.getEntryCount(), 1);

    assertEquals(searchResult.getReferenceCount(), 0);

    assertNotNull(searchResult.getSearchEntries());
    assertEquals(searchResult.getSearchEntries().size(),
                 searchResult.getEntryCount());

    assertNotNull(searchResult.getSearchEntry("dc=example,dc=com"));

    assertNotNull(searchResult.getSearchReferences());
    assertEquals(searchResult.getSearchReferences().size(),
                 searchResult.getReferenceCount());

    assertNotNull(searchResult.getResponseControls());
    assertEquals(searchResult.getResponseControls().length, 0);

    assertNotNull(searchResult.toString());
  }



  /**
   * Tests the second constructor by simulating a failed search with entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2FailedWithEntries()
         throws Exception
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResult searchResult =
         new SearchResult(1, ResultCode.NO_SUCH_OBJECT,
                          "The specified entry does not exist.",
                          "dc=example,dc=com", referralURLs,
                          new ArrayList<SearchResultEntry>(0),
                          new ArrayList<SearchResultReference>(0), 0, 0,
                          controls);

    assertEquals(searchResult.getMessageID(), 1);

    assertEquals(searchResult.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(searchResult.getDiagnosticMessage());
    assertEquals(searchResult.getDiagnosticMessage(),
                 "The specified entry does not exist.");

    assertNotNull(searchResult.getMatchedDN());
    assertEquals(searchResult.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(searchResult.getReferralURLs());
    assertEquals(searchResult.getReferralURLs().length, 2);

    assertEquals(searchResult.getEntryCount(), 0);

    assertEquals(searchResult.getReferenceCount(), 0);

    assertNotNull(searchResult.getSearchEntries());
    assertEquals(searchResult.getSearchEntries().size(),
                 searchResult.getEntryCount());

    assertNull(searchResult.getSearchEntry("dc=example,dc=com"));

    assertNotNull(searchResult.getSearchReferences());
    assertEquals(searchResult.getSearchReferences().size(),
                 searchResult.getReferenceCount());

    assertNotNull(searchResult.getResponseControls());
    assertEquals(searchResult.getResponseControls().length, 2);

    assertNotNull(searchResult.toString());
  }



  /**
   * Tests the second constructor by simulating a successful search without
   * entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SuccessfulWithoutEntries()
         throws Exception
  {
    SearchResult searchResult =
         new SearchResult(1, ResultCode.SUCCESS, null, null, null, null, null,
                          10, 1, null);

    assertEquals(searchResult.getMessageID(), 1);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertNull(searchResult.getDiagnosticMessage());

    assertNull(searchResult.getMatchedDN());

    assertNotNull(searchResult.getReferralURLs());
    assertEquals(searchResult.getReferralURLs().length, 0);

    assertEquals(searchResult.getEntryCount(), 10);

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNull(searchResult.getSearchEntries());

    assertNull(searchResult.getSearchEntry("dc=example,dc=com"));

    assertNull(searchResult.getSearchReferences());

    assertNotNull(searchResult.getResponseControls());
    assertEquals(searchResult.getResponseControls().length, 0);

    assertNotNull(searchResult.toString());
  }



  /**
   * Tests the second constructor by simulating a failed search without entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2FailedWithoutEntries()
         throws Exception
  {
    String[] referralURLs =
    {
      "ldap://test1.example.com/dc=example,dc=com",
      "ldap://test2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResult searchResult =
         new SearchResult(1, ResultCode.NO_SUCH_OBJECT,
                          "The specified entry does not exist.",
                          "dc=example,dc=com", referralURLs, null, null, 0, 0,
                          controls);

    assertEquals(searchResult.getMessageID(), 1);

    assertEquals(searchResult.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(searchResult.getDiagnosticMessage());
    assertEquals(searchResult.getDiagnosticMessage(),
                 "The specified entry does not exist.");

    assertNotNull(searchResult.getMatchedDN());
    assertEquals(searchResult.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(searchResult.getReferralURLs());
    assertEquals(searchResult.getReferralURLs().length, 2);

    assertEquals(searchResult.getEntryCount(), 0);

    assertEquals(searchResult.getReferenceCount(), 0);

    assertNull(searchResult.getSearchEntries());

    assertNull(searchResult.getSearchEntry("dc=example,dc=com"));

    assertNull(searchResult.getSearchReferences());

    assertNotNull(searchResult.getResponseControls());
    assertEquals(searchResult.getResponseControls().length, 2);

    assertNotNull(searchResult.toString());
  }
}
