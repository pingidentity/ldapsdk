/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.util.NoSuchElementException;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;



/**
 * This class provides test coverage for the {@code LDAPSearchResults} class.
 */
public class LDAPSearchResultsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a basic set of tests for an {@code LDAPSearchResults} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasic()
         throws Exception
  {
    LDAPSearchResults results = new LDAPSearchResults();

    results.searchEntryReturned(new SearchResultEntry(1, new Entry(
         "dn: ou=entry 1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: entry 1")));

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true)
    };
    results.searchEntryReturned(new SearchResultEntry(1, new Entry(
         "dn: ou=entry 2,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: entry 2"), controls));

    String[] refs =
    {
      "ldap://server1.example.com:389/dc=example,dc=com",
      "ldap://server2.example.com:389/dc=example,dc=com"
    };
    results.searchReferenceReturned(new SearchResultReference(1, refs, null));

    refs = new String[]
    {
      "ldap://server3.example.com:389/dc=example,dc=com",
      "ldap://server4.example.com:389/dc=example,dc=com"
    };
    results.searchReferenceReturned(new SearchResultReference(1, refs,
         controls));

    results.searchResultReceived(
         InternalSDKHelper.createAsyncRequestID(1, null),
         new SearchResult(1, ResultCode.SUCCESS, null, null, null, 2, 2, null));

    assertTrue(results.hasMoreElements());
    assertEquals(results.getCount(), 4);

    LDAPEntry e = results.next();
    assertNotNull(e);
    assertEquals(e.getDN(), "ou=entry 1,dc=example,dc=com");
    assertNull(results.getResponseControls());

    assertTrue(results.hasMoreElements());
    assertEquals(results.getCount(), 3);

    e = (LDAPEntry) results.nextElement();
    assertNotNull(e);
    assertEquals(e.getDN(), "ou=entry 2,dc=example,dc=com");
    assertNotNull(results.getResponseControls());
    assertEquals(results.getResponseControls().length, 2);

    assertTrue(results.hasMoreElements());
    assertEquals(results.getCount(), 2);

    try
    {

      results.next();
      fail("Expected an exception when next() is a reference");
    }
    catch (LDAPException le)
    {
      assertTrue(le instanceof LDAPReferralException);
    }
    assertNull(results.getResponseControls());

    assertTrue(results.hasMoreElements());
    assertEquals(results.getCount(), 1);

    assertTrue(results.nextElement() instanceof LDAPReferralException);
    assertNotNull(results.getResponseControls());
    assertEquals(results.getResponseControls().length, 2);

    assertFalse(results.hasMoreElements());
    assertEquals(results.getCount(), 0);

    assertFalse(results.hasMoreElements());
    assertEquals(results.getCount(), 0);

    try
    {
      results.nextElement();
      fail("Expected an exception from nextElement() with no more results");
    }
    catch (NoSuchElementException nsee)
    {
      // This was expected.
    }

    try
    {
      results.next();
      fail("Expected an exception from next() with no more results");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }


    results.searchEntryReturned(new SearchResultEntry(1, new Entry(
         "dn: ou=entry 3,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: entry 3")));

    assertFalse(results.hasMoreElements());
    assertEquals(results.getCount(), 0);


    results.searchReferenceReturned(new SearchResultReference(1, refs, null));

    assertFalse(results.hasMoreElements());
    assertEquals(results.getCount(), 0);

    results.searchResultReceived(
         InternalSDKHelper.createAsyncRequestID(1, null),
         new SearchResult(1, ResultCode.SUCCESS, null, null, null, 2, 2, null));

    assertFalse(results.hasMoreElements());
    assertEquals(results.getCount(), 0);
  }



  /**
   * Performs a test with a failed result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRailedResult()
         throws Exception
  {
    LDAPSearchResults results = new LDAPSearchResults();

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true)
    };
    results.searchResultReceived(
         InternalSDKHelper.createAsyncRequestID(1, null),
         new SearchResult(1, ResultCode.NO_SUCH_OBJECT, null,
              "dc=example,dc=com", null, 0, 0, controls));

    assertTrue(results.hasMoreElements());
    assertEquals(results.getCount(), 1);

    Object o = results.nextElement();
    assertNotNull(o);
    assertTrue(o instanceof LDAPException);
    assertNotNull(results.getResponseControls());

    assertFalse(results.hasMoreElements());
    assertEquals(results.getCount(), 0);

    try
    {
      results.nextElement();
      fail("Expected an exception from nextElement() with no more results");
    }
    catch (NoSuchElementException nsee)
    {
      // This was expected.
    }

    try
    {
      results.next();
      fail("Expected an exception from next() with no more results");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Performs a test with a delayed result when there is no timeout.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDelayWithoutTimeout()
         throws Exception
  {
    LDAPSearchResults results = new LDAPSearchResults();

    TestDelayedResultProvider provider =
         new TestDelayedResultProvider(results, 1000);
    provider.start();

    assertTrue(results.hasMoreElements());
    assertEquals(results.getCount(), 1);

    Object o = results.nextElement();
    assertTrue(o instanceof LDAPException);

    assertFalse(results.hasMoreElements());
    assertEquals(results.getCount(), 0);
  }



  /**
   * Performs a test with a delayed result when there is a timeout and it has
   * not been reached.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDelayWithUnreachedTimeout()
         throws Exception
  {
    LDAPSearchResults results = new LDAPSearchResults(5000L);

    TestDelayedResultProvider provider =
         new TestDelayedResultProvider(results, 1000);
    provider.start();

    assertTrue(results.hasMoreElements());
    assertEquals(results.getCount(), 1);

    Object o = results.nextElement();
    assertTrue(o instanceof LDAPException);

    assertFalse(results.hasMoreElements());
    assertEquals(results.getCount(), 0);
  }



  /**
   * Performs a test with a delayed result when there is a timeout and it has
   * not been reached.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDelayWithReachedTimeout()
         throws Exception
  {
    LDAPSearchResults results = new LDAPSearchResults(100L);

    assertTrue(results.hasMoreElements());
    assertEquals(results.getCount(), 1);

    Object o = results.nextElement();
    assertTrue(o instanceof LDAPException);

    assertFalse(results.hasMoreElements());
    assertEquals(results.getCount(), 0);
  }
}
