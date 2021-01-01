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
package com.unboundid.ldap.sdk;



import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;



/**
 * Provides a set of test cases for the {@code LDAPConnectionStatistics} class.
 */
public class LDAPConnectionStatisticsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Adds a test entry to the directory.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.close();
  }



  /**
   * Removes the test entry from the directory.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Performs a set of tests that can be invoked without a directory instance
   * available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStanalone()
         throws Exception
  {
    LDAPConnectionStatistics stats = new LDAPConnectionStatistics();

    assertNotNull(stats.toString());

    assertEquals(stats.getNumConnects(), 0L);
    assertEquals(stats.getNumDisconnects(), 0L);

    assertEquals(stats.getNumAbandonRequests(), 0L);

    assertEquals(stats.getNumAddRequests(), 0L);
    assertEquals(stats.getNumAddResponses(), 0L);
    assertEquals(stats.getTotalAddResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalAddResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageAddResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageAddResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumBindRequests(), 0L);
    assertEquals(stats.getNumBindResponses(), 0L);
    assertEquals(stats.getTotalBindResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalBindResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageBindResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageBindResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumCompareRequests(), 0L);
    assertEquals(stats.getNumCompareResponses(), 0L);
    assertEquals(stats.getTotalCompareResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalCompareResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageCompareResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageCompareResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumDeleteRequests(), 0L);
    assertEquals(stats.getNumDeleteResponses(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageDeleteResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageDeleteResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumExtendedRequests(), 0L);
    assertEquals(stats.getNumExtendedResponses(), 0L);
    assertEquals(stats.getTotalExtendedResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalExtendedResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageExtendedResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageExtendedResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumModifyRequests(), 0L);
    assertEquals(stats.getNumModifyResponses(), 0L);
    assertEquals(stats.getTotalModifyResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalModifyResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageModifyResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageModifyResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumModifyDNRequests(), 0L);
    assertEquals(stats.getNumModifyDNResponses(), 0L);
    assertEquals(stats.getTotalModifyDNResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalModifyDNResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageModifyDNResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageModifyDNResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumSearchRequests(), 0L);
    assertEquals(stats.getNumSearchEntryResponses(), 0L);
    assertEquals(stats.getNumSearchReferenceResponses(), 0L);
    assertEquals(stats.getNumSearchDoneResponses(), 0L);
    assertEquals(stats.getTotalSearchResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalSearchResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageSearchResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageSearchResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumUnbindRequests(), 0L);

    assertEquals(stats.getNumConnects(), 0L);
    stats.incrementNumConnects();
    assertEquals(stats.getNumConnects(), 1L);

    assertEquals(stats.getNumDisconnects(), 0L);
    stats.incrementNumDisconnects();
    assertEquals(stats.getNumDisconnects(), 1L);

    assertEquals(stats.getNumAbandonRequests(), 0L);
    stats.incrementNumAbandonRequests();
    assertEquals(stats.getNumAbandonRequests(), 1L);

    assertEquals(stats.getNumAddRequests(), 0L);
    stats.incrementNumAddRequests();
    assertEquals(stats.getNumAddRequests(), 1L);

    assertEquals(stats.getNumAddResponses(), 0L);
    assertEquals(stats.getTotalAddResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalAddResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageAddResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageAddResponseTimeMillis(), Double.NaN);
    stats.incrementNumAddResponses(1234567L);
    assertEquals(stats.getNumAddResponses(), 1L);
    assertEquals(stats.getTotalAddResponseTimeNanos(), 1234567L);
    assertEquals(stats.getTotalAddResponseTimeMillis(), 1L);
    assertEquals(stats.getAverageAddResponseTimeNanos(),
                 (1.0d * 1234567L / 1L));
    assertEquals(stats.getAverageAddResponseTimeMillis(),
                 (1234567L / 1000000.0d / 1L));

    assertEquals(stats.getNumBindRequests(), 0L);
    stats.incrementNumBindRequests();
    assertEquals(stats.getNumBindRequests(), 1L);

    assertEquals(stats.getNumBindResponses(), 0L);
    assertEquals(stats.getTotalBindResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalBindResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageBindResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageBindResponseTimeMillis(), Double.NaN);
    stats.incrementNumBindResponses(1234567L);
    assertEquals(stats.getNumBindResponses(), 1L);
    assertEquals(stats.getTotalBindResponseTimeNanos(), 1234567L);
    assertEquals(stats.getTotalBindResponseTimeMillis(), 1L);
    assertEquals(stats.getAverageBindResponseTimeNanos(),
                 (1.0d * 1234567L / 1L));
    assertEquals(stats.getAverageBindResponseTimeMillis(),
                 (1234567L / 1000000.0d / 1L));

    assertEquals(stats.getNumCompareRequests(), 0L);
    stats.incrementNumCompareRequests();
    assertEquals(stats.getNumCompareRequests(), 1L);

    assertEquals(stats.getNumCompareResponses(), 0L);
    assertEquals(stats.getTotalCompareResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalCompareResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageCompareResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageCompareResponseTimeMillis(), Double.NaN);
    stats.incrementNumCompareResponses(1234567L);
    assertEquals(stats.getNumCompareResponses(), 1L);
    assertEquals(stats.getTotalCompareResponseTimeNanos(), 1234567L);
    assertEquals(stats.getTotalCompareResponseTimeMillis(), 1L);
    assertEquals(stats.getAverageCompareResponseTimeNanos(),
                 (1.0d * 1234567L / 1L));
    assertEquals(stats.getAverageCompareResponseTimeMillis(),
                 (1234567L / 1000000.0d / 1L));

    assertEquals(stats.getNumDeleteRequests(), 0L);
    stats.incrementNumDeleteRequests();
    assertEquals(stats.getNumDeleteRequests(), 1L);

    assertEquals(stats.getNumDeleteResponses(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageDeleteResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageDeleteResponseTimeMillis(), Double.NaN);
    stats.incrementNumDeleteResponses(1234567L);
    assertEquals(stats.getNumDeleteResponses(), 1L);
    assertEquals(stats.getTotalDeleteResponseTimeNanos(), 1234567L);
    assertEquals(stats.getTotalDeleteResponseTimeMillis(), 1L);
    assertEquals(stats.getAverageDeleteResponseTimeNanos(),
                 (1.0d * 1234567L / 1L));
    assertEquals(stats.getAverageDeleteResponseTimeMillis(),
                 (1234567L / 1000000.0d / 1L));

    assertEquals(stats.getNumExtendedRequests(), 0L);
    stats.incrementNumExtendedRequests();
    assertEquals(stats.getNumExtendedRequests(), 1L);

    assertEquals(stats.getNumExtendedResponses(), 0L);
    assertEquals(stats.getTotalExtendedResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalExtendedResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageExtendedResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageExtendedResponseTimeMillis(), Double.NaN);
    stats.incrementNumExtendedResponses(1234567L);
    assertEquals(stats.getNumExtendedResponses(), 1L);
    assertEquals(stats.getTotalExtendedResponseTimeNanos(), 1234567L);
    assertEquals(stats.getTotalExtendedResponseTimeMillis(), 1L);
    assertEquals(stats.getAverageExtendedResponseTimeNanos(),
                 (1.0d * 1234567L / 1L));
    assertEquals(stats.getAverageExtendedResponseTimeMillis(),
                 (1234567L / 1000000.0d / 1L));

    assertEquals(stats.getNumModifyRequests(), 0L);
    stats.incrementNumModifyRequests();
    assertEquals(stats.getNumModifyRequests(), 1L);

    assertEquals(stats.getNumModifyResponses(), 0L);
    assertEquals(stats.getTotalModifyResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalModifyResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageModifyResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageModifyResponseTimeMillis(), Double.NaN);
    stats.incrementNumModifyResponses(1234567L);
    assertEquals(stats.getNumModifyResponses(), 1L);
    assertEquals(stats.getTotalModifyResponseTimeNanos(), 1234567L);
    assertEquals(stats.getTotalModifyResponseTimeMillis(), 1L);
    assertEquals(stats.getAverageModifyResponseTimeNanos(),
                 (1.0d * 1234567L / 1L));
    assertEquals(stats.getAverageModifyResponseTimeMillis(),
                 (1234567L / 1000000.0d / 1L));

    assertEquals(stats.getNumModifyDNRequests(), 0L);
    stats.incrementNumModifyDNRequests();
    assertEquals(stats.getNumModifyDNRequests(), 1L);

    assertEquals(stats.getNumModifyDNResponses(), 0L);
    assertEquals(stats.getTotalModifyDNResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalModifyDNResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageModifyDNResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageModifyDNResponseTimeMillis(), Double.NaN);
    stats.incrementNumModifyDNResponses(1234567L);
    assertEquals(stats.getNumModifyDNResponses(), 1L);
    assertEquals(stats.getTotalModifyDNResponseTimeNanos(), 1234567L);
    assertEquals(stats.getTotalModifyDNResponseTimeMillis(), 1L);
    assertEquals(stats.getAverageModifyDNResponseTimeNanos(),
                 (1.0d * 1234567L / 1L));
    assertEquals(stats.getAverageModifyDNResponseTimeMillis(),
                 (1234567L / 1000000.0d / 1L));

    assertEquals(stats.getNumSearchRequests(), 0L);
    stats.incrementNumSearchRequests();
    assertEquals(stats.getNumSearchRequests(), 1L);

    assertEquals(stats.getNumSearchEntryResponses(), 0L);
    assertEquals(stats.getNumSearchReferenceResponses(), 0L);
    assertEquals(stats.getNumSearchDoneResponses(), 0L);
    assertEquals(stats.getTotalSearchResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalSearchResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageSearchResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageSearchResponseTimeMillis(), Double.NaN);
    stats.incrementNumSearchResponses(3, 2, 1234567L);
    assertEquals(stats.getNumSearchEntryResponses(), 3L);
    assertEquals(stats.getNumSearchReferenceResponses(), 2L);
    assertEquals(stats.getNumSearchDoneResponses(), 1L);
    assertEquals(stats.getTotalSearchResponseTimeNanos(), 1234567L);
    assertEquals(stats.getTotalSearchResponseTimeMillis(), 1L);
    assertEquals(stats.getAverageSearchResponseTimeNanos(),
                 (1.0d * 1234567L / 1L));
    assertEquals(stats.getAverageSearchResponseTimeMillis(),
                 (1234567L / 1000000.0d / 1L));

    assertNotNull(stats.toString());

    stats.reset();

    assertNotNull(stats.toString());

    assertEquals(stats.getNumConnects(), 0L);
    assertEquals(stats.getNumDisconnects(), 0L);

    assertEquals(stats.getNumAbandonRequests(), 0L);

    assertEquals(stats.getNumAddRequests(), 0L);
    assertEquals(stats.getNumAddResponses(), 0L);
    assertEquals(stats.getTotalAddResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalAddResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageAddResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageAddResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumBindRequests(), 0L);
    assertEquals(stats.getNumBindResponses(), 0L);
    assertEquals(stats.getTotalBindResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalBindResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageBindResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageBindResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumCompareRequests(), 0L);
    assertEquals(stats.getNumCompareResponses(), 0L);
    assertEquals(stats.getTotalCompareResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalCompareResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageCompareResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageCompareResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumDeleteRequests(), 0L);
    assertEquals(stats.getNumDeleteResponses(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageDeleteResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageDeleteResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumExtendedRequests(), 0L);
    assertEquals(stats.getNumExtendedResponses(), 0L);
    assertEquals(stats.getTotalExtendedResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalExtendedResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageExtendedResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageExtendedResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumModifyRequests(), 0L);
    assertEquals(stats.getNumModifyResponses(), 0L);
    assertEquals(stats.getTotalModifyResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalModifyResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageModifyResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageModifyResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumModifyDNRequests(), 0L);
    assertEquals(stats.getNumModifyDNResponses(), 0L);
    assertEquals(stats.getTotalModifyDNResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalModifyDNResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageModifyDNResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageModifyDNResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumSearchRequests(), 0L);
    assertEquals(stats.getNumSearchEntryResponses(), 0L);
    assertEquals(stats.getNumSearchReferenceResponses(), 0L);
    assertEquals(stats.getNumSearchDoneResponses(), 0L);
    assertEquals(stats.getTotalSearchResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalSearchResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageSearchResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageSearchResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumUnbindRequests(), 0L);
  }



  /**
   * Tests to ensure that connection statistics are properly maintained for
   * connection establishment and termination.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectAndDisconnect()
         throws Exception
  {
    LDAPConnection           conn  = new LDAPConnection();
    LDAPConnectionStatistics stats = conn.getConnectionStatistics();

    assertEquals(stats.getNumConnects(), 0L);
    assertEquals(stats.getNumDisconnects(), 0L);

    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    conn.connect(getTestHost(), getTestPort());
    assertEquals(stats.getNumConnects(), 1L);
    assertEquals(stats.getNumDisconnects(), 0L);

    conn.connect(getTestHost(), getTestPort());
    assertEquals(stats.getNumConnects(), 2L);
    assertTrue(stats.getNumDisconnects() >= 1L);

    conn.close();
    assertEquals(stats.getNumConnects(), 2L);
    assertTrue(stats.getNumDisconnects() >= 2L);
  }



  /**
   * Tests to ensure that connection statistics are properly maintained for
   * abandon requests.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbandonRequest()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection           conn  = getAdminConnection();
    LDAPConnectionStatistics stats = conn.getConnectionStatistics();

    assertEquals(stats.getNumSearchRequests(), 0L);
    assertEquals(stats.getNumAbandonRequests(), 0L);

    SearchRequest searchRequest =
         new SearchRequest(new TestAsyncListener(), "", SearchScope.BASE,
                           "(objectClass=*)");
    AsyncRequestID asyncRequestID = conn.asyncSearch(searchRequest);
    conn.abandon(asyncRequestID);

    assertEquals(stats.getNumSearchRequests(), 1L);
    assertEquals(stats.getNumAbandonRequests(), 1L);

    conn.close();
  }



  /**
   * Tests to ensure that connection statistics are properly maintained for add,
   * modify DN, and delete requests.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddModDNAndDelete()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection           conn  = getAdminConnection();
    LDAPConnectionStatistics stats = conn.getConnectionStatistics();

    assertEquals(stats.getNumAddRequests(), 0L);
    assertEquals(stats.getNumAddResponses(), 0L);
    assertEquals(stats.getTotalAddResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalAddResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageAddResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageAddResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumModifyDNRequests(), 0L);
    assertEquals(stats.getNumModifyDNResponses(), 0L);
    assertEquals(stats.getTotalModifyDNResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalModifyDNResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageModifyDNResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageModifyDNResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumDeleteRequests(), 0L);
    assertEquals(stats.getNumDeleteResponses(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageDeleteResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageDeleteResponseTimeMillis(), Double.NaN);

    conn.add("dn: ou=test," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: test");

    assertEquals(stats.getNumAddRequests(), 1L);
    assertEquals(stats.getNumAddResponses(), 1L);
    assertTrue(stats.getTotalAddResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageAddResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageAddResponseTimeMillis() == Double.NaN);

    assertEquals(stats.getNumModifyDNRequests(), 0L);
    assertEquals(stats.getNumModifyDNResponses(), 0L);
    assertEquals(stats.getTotalModifyDNResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalModifyDNResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageModifyDNResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageModifyDNResponseTimeMillis(), Double.NaN);

    assertEquals(stats.getNumDeleteRequests(), 0L);
    assertEquals(stats.getNumDeleteResponses(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageDeleteResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageDeleteResponseTimeMillis(), Double.NaN);

    conn.modifyDN("ou=test," + getTestBaseDN(), "ou=test2", true);

    assertEquals(stats.getNumAddRequests(), 1L);
    assertEquals(stats.getNumAddResponses(), 1L);
    assertTrue(stats.getTotalAddResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageAddResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageAddResponseTimeMillis() == Double.NaN);

    assertEquals(stats.getNumModifyDNRequests(), 1L);
    assertEquals(stats.getNumModifyDNResponses(), 1L);
    assertTrue(stats.getTotalModifyDNResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageModifyDNResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageModifyDNResponseTimeMillis() == Double.NaN);

    assertEquals(stats.getNumDeleteRequests(), 0L);
    assertEquals(stats.getNumDeleteResponses(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalDeleteResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageDeleteResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageDeleteResponseTimeMillis(), Double.NaN);

    conn.delete("ou=test2," + getTestBaseDN());

    assertEquals(stats.getNumAddRequests(), 1L);
    assertEquals(stats.getNumAddResponses(), 1L);
    assertTrue(stats.getTotalAddResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageAddResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageAddResponseTimeMillis() == Double.NaN);

    assertEquals(stats.getNumModifyDNRequests(), 1L);
    assertEquals(stats.getNumModifyDNResponses(), 1L);
    assertTrue(stats.getTotalModifyDNResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageModifyDNResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageModifyDNResponseTimeMillis() == Double.NaN);

    assertEquals(stats.getNumDeleteRequests(), 1L);
    assertEquals(stats.getNumDeleteResponses(), 1L);
    assertTrue(stats.getTotalDeleteResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageDeleteResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageDeleteResponseTimeMillis() == Double.NaN);

    conn.close();
  }



  /**
   * Tests to ensure that connection statistics are properly maintained for a
   * simple bind request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleBind()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection           conn  = getUnauthenticatedConnection();
    LDAPConnectionStatistics stats = conn.getConnectionStatistics();

    assertEquals(stats.getNumBindRequests(), 0L);
    assertEquals(stats.getNumBindResponses(), 0L);
    assertEquals(stats.getTotalBindResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalBindResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageBindResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageBindResponseTimeMillis(), Double.NaN);

    conn.bind(getTestBindDN(), getTestBindPassword());

    assertEquals(stats.getNumBindRequests(), 1L);
    assertEquals(stats.getNumBindResponses(), 1L);
    assertTrue(stats.getTotalBindResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageBindResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageBindResponseTimeMillis() == Double.NaN);

    conn.close();
  }



  /**
   * Tests to ensure that connection statistics are properly maintained for a
   * SASL PLAIN bind request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPLAINBind()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection           conn  = getUnauthenticatedConnection();
    LDAPConnectionStatistics stats = conn.getConnectionStatistics();

    assertEquals(stats.getNumBindRequests(), 0L);
    assertEquals(stats.getNumBindResponses(), 0L);
    assertEquals(stats.getTotalBindResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalBindResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageBindResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageBindResponseTimeMillis(), Double.NaN);

    conn.bind(new PLAINBindRequest("dn:" + getTestBindDN(),
                                   getTestBindPassword()));

    assertEquals(stats.getNumBindRequests(), 1L);
    assertEquals(stats.getNumBindResponses(), 1L);
    assertTrue(stats.getTotalBindResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageBindResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageBindResponseTimeMillis() == Double.NaN);

    conn.close();
  }



  /**
   * Tests to ensure that connection statistics are properly maintained for a
   * compare request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompare()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection           conn  = getAdminConnection();
    LDAPConnectionStatistics stats = conn.getConnectionStatistics();

    assertEquals(stats.getNumCompareRequests(), 0L);
    assertEquals(stats.getNumCompareResponses(), 0L);
    assertEquals(stats.getTotalCompareResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalCompareResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageCompareResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageCompareResponseTimeMillis(), Double.NaN);

    conn.compare(getTestBaseDN(), "objectClass", "top");

    assertEquals(stats.getNumCompareRequests(), 1L);
    assertEquals(stats.getNumCompareResponses(), 1L);
    assertTrue(stats.getTotalCompareResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageCompareResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageCompareResponseTimeMillis() == Double.NaN);

    conn.close();
  }



  /**
   * Tests to ensure that connection statistics are properly maintained for a
   * modify request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModify()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection           conn  = getAdminConnection();
    LDAPConnectionStatistics stats = conn.getConnectionStatistics();

    assertEquals(stats.getNumModifyRequests(), 0L);
    assertEquals(stats.getNumModifyResponses(), 0L);
    assertEquals(stats.getTotalModifyResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalModifyResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageModifyResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageModifyResponseTimeMillis(), Double.NaN);

    conn.modify("dn: " + getTestBaseDN(),
                "changetype: modify",
                "replace: description",
                "description: foo");

    assertEquals(stats.getNumModifyRequests(), 1L);
    assertEquals(stats.getNumModifyResponses(), 1L);
    assertTrue(stats.getTotalModifyResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageModifyResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageModifyResponseTimeMillis() == Double.NaN);

    conn.close();
  }



  /**
   * Tests to ensure that connection statistics are properly maintained for a
   * search request that does not match any entries.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchNoEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection           conn  = getAdminConnection();
    LDAPConnectionStatistics stats = conn.getConnectionStatistics();

    assertEquals(stats.getNumSearchRequests(), 0L);
    assertEquals(stats.getNumSearchEntryResponses(), 0L);
    assertEquals(stats.getNumSearchReferenceResponses(), 0L);
    assertEquals(stats.getNumSearchDoneResponses(), 0L);
    assertEquals(stats.getTotalSearchResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalSearchResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageSearchResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageSearchResponseTimeMillis(), Double.NaN);

    conn.search(getTestBaseDN(), SearchScope.BASE,
                "(objectClass=doesNotMatch)");

    assertEquals(stats.getNumSearchRequests(), 1L);
    assertEquals(stats.getNumSearchEntryResponses(), 0L);
    assertEquals(stats.getNumSearchReferenceResponses(), 0L);
    assertEquals(stats.getNumSearchDoneResponses(), 1L);
    assertTrue(stats.getTotalSearchResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageSearchResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageSearchResponseTimeMillis() == Double.NaN);

    conn.close();
  }



  /**
   * Tests to ensure that connection statistics are properly maintained for a
   * search request that does matches an entry.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchOneEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection           conn  = getAdminConnection();
    LDAPConnectionStatistics stats = conn.getConnectionStatistics();

    assertEquals(stats.getNumSearchRequests(), 0L);
    assertEquals(stats.getNumSearchEntryResponses(), 0L);
    assertEquals(stats.getNumSearchReferenceResponses(), 0L);
    assertEquals(stats.getNumSearchDoneResponses(), 0L);
    assertEquals(stats.getTotalSearchResponseTimeNanos(), 0L);
    assertEquals(stats.getTotalSearchResponseTimeMillis(), 0L);
    assertEquals(stats.getAverageSearchResponseTimeNanos(), Double.NaN);
    assertEquals(stats.getAverageSearchResponseTimeMillis(), Double.NaN);

    conn.search(getTestBaseDN(), SearchScope.BASE, "(objectClass=*)");

    assertEquals(stats.getNumSearchRequests(), 1L);
    assertEquals(stats.getNumSearchEntryResponses(), 1L);
    assertEquals(stats.getNumSearchReferenceResponses(), 0L);
    assertEquals(stats.getNumSearchDoneResponses(), 1L);
    assertTrue(stats.getTotalSearchResponseTimeNanos() > 0L);
    assertFalse(stats.getAverageSearchResponseTimeNanos() == Double.NaN);
    assertFalse(stats.getAverageSearchResponseTimeMillis() == Double.NaN);

    conn.close();
  }
}
