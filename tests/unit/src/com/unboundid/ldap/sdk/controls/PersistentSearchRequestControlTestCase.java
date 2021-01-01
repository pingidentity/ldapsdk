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
package com.unboundid.ldap.sdk.controls;



import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AsyncRequestID;
import com.unboundid.ldap.sdk.AsyncSearchResultListener;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.extensions.CancelExtendedRequest;



/**
 * This class provides a set of test cases for the
 * PersistentSearchRequestControl class.
 */
public class PersistentSearchRequestControlTestCase
       extends LDAPSDKTestCase
       implements AsyncSearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5760357037403585722L;



  // The number of search result entries that have been returned.
  private final List<SearchResultEntry> persistentSearchEntries =
       new CopyOnWriteArrayList<SearchResultEntry>();



  /**
   * Test the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    PersistentSearchRequestControl c =
         new PersistentSearchRequestControl(PersistentSearchChangeType.MODIFY,
                                            true, true);
    c = new PersistentSearchRequestControl(c);

    assertNotNull(c.getChangeTypes());
    assertEquals(c.getChangeTypes().size(), 1);

    assertTrue(c.changesOnly());

    assertTrue(c.returnECs());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Test the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    PersistentSearchRequestControl c =
         new PersistentSearchRequestControl(
                  PersistentSearchChangeType.allChangeTypes(), true, true);
    c = new PersistentSearchRequestControl(c);

    assertNotNull(c.getChangeTypes());
    assertEquals(c.getChangeTypes().size(), 4);

    assertTrue(c.changesOnly());

    assertTrue(c.returnECs());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Test the third constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    PersistentSearchRequestControl c =
         new PersistentSearchRequestControl(PersistentSearchChangeType.MODIFY,
                                            true, true, false);
    c = new PersistentSearchRequestControl(c);

    assertNotNull(c.getChangeTypes());
    assertEquals(c.getChangeTypes().size(), 1);

    assertTrue(c.changesOnly());

    assertTrue(c.returnECs());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Test the fourth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    PersistentSearchRequestControl c =
         new PersistentSearchRequestControl(
                  PersistentSearchChangeType.allChangeTypes(), true, true,
                  false);
    c = new PersistentSearchRequestControl(c);

    assertNotNull(c.getChangeTypes());
    assertEquals(c.getChangeTypes().size(), 4);

    assertTrue(c.changesOnly());

    assertTrue(c.returnECs());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor with a generic control that does not contain a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor5NoValue()
         throws Exception
  {
    Control c = new Control(PersistentSearchRequestControl.
                                 PERSISTENT_SEARCH_REQUEST_OID,
                            true, null);
    new PersistentSearchRequestControl(c);
  }



  /**
   * Tests the fifth constructor with a generic control with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor5InvalidValue()
         throws Exception
  {
    Control c = new Control(PersistentSearchRequestControl.
                                 PERSISTENT_SEARCH_REQUEST_OID,
                            true, new ASN1OctetString("foo"));
    new PersistentSearchRequestControl(c);
  }



  /**
   * Sends a search request to the server with an assertion control that
   * contains a non-matching filter.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithPersistentSearchControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // This is necessary if we invoke this method with (invocationCount > 1).
    persistentSearchEntries.clear();

    final LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());


    // Start an asynchronous persistent search.  Include "changesOnly=false" so
    // that the existing entry will be returned.  This will be used as a flag to
    // indicate that the search has started.
    final SearchRequest searchRequest = new SearchRequest(this, getTestBaseDN(),
         SearchScope.BASE, Filter.createPresenceFilter("objectClass"), "1.1");
    searchRequest.addControl(new PersistentSearchRequestControl(
         PersistentSearchChangeType.allChangeTypes(), false, true, true));

    final AsyncRequestID asyncRequestID = conn.asyncSearch(searchRequest);


    // Wait for a search result entry to appear.  This will signal that the
    // search has started.
    long stopWaitingTime = System.currentTimeMillis() + 30000L;
    while (System.currentTimeMillis() < stopWaitingTime)
    {
      if (! persistentSearchEntries.isEmpty())
      {
        break;
      }
      Thread.sleep(1L);
    }
    assertFalse(persistentSearchEntries.isEmpty());
    assertEquals(persistentSearchEntries.size(), 1);


    // Apply a change to the base entry.
    conn.modify(
         "dn: " + getTestBaseDN(),
         "changetype: modify",
         "replace: description",
         "description: foo");


    // Wait for the change to be returned by the persistent search.
    stopWaitingTime = System.currentTimeMillis() + 30000L;
    while (System.currentTimeMillis() < stopWaitingTime)
    {
      if (persistentSearchEntries.size() == 2)
      {
        break;
      }
      Thread.sleep(1L);
    }
    assertEquals(persistentSearchEntries.size(), 2);


    // Cancel the asynchronous search.
    assertResultCodeEquals(conn,
         new CancelExtendedRequest(asyncRequestID),
         ResultCode.CANCELED);


    // NOTE:  The following lines are commented out because some versions of the
    //        UnboundID Directory Server suffer from a bug that prevented it
    //        from returning a result to a canceled persistent search.
/*
    // Get the search result.
    final LDAPResult genericResult =
         asyncRequestID.get(30L, TimeUnit.SECONDS);
    assertNotNull(genericResult);
    assertTrue(genericResult instanceof SearchResult);

    final SearchResult searchResult = (SearchResult) genericResult;
    assertEquals(searchResult.getResultCode(), ResultCode.CANCELED);
    assertEquals(searchResult.getEntryCount(), 2);
 */

    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * {@inheritDoc}
   */
  @Test(enabled=false) // Tell TestNG that this isn't a test method.
  @Override()
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    persistentSearchEntries.add(searchEntry);
  }



  /**
   * {@inheritDoc}
   */
  @Test(enabled=false) // Tell TestNG that this isn't a test method.
  @Override()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    // No implementation is required.
  }



  /**
   * {@inheritDoc}
   */
  @Test(enabled=false) // Tell TestNG that this isn't a test method.
  @Override()
  public void searchResultReceived(final AsyncRequestID requestID,
                                   final SearchResult searchResult)
  {
    // No implementation is required.
  }
}
