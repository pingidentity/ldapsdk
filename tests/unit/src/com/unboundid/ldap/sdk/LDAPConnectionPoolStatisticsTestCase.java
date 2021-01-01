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
 * This class provides a set of test cases for the
 * {@code LDAPConnectionPoolStatistics} class.
 */
public class LDAPConnectionPoolStatisticsTestCase
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
    LDAPConnectionPoolStatistics stats = new LDAPConnectionPoolStatistics(null);

    assertEquals(stats.getNumSuccessfulConnectionAttempts(), 0L);
    assertEquals(stats.getNumFailedConnectionAttempts(), 0L);

    assertEquals(stats.getNumConnectionsClosedDefunct(), 0L);
    assertEquals(stats.getNumConnectionsClosedExpired(), 0L);
    assertEquals(stats.getNumConnectionsClosedUnneeded(), 0L);

    assertEquals(stats.getNumSuccessfulCheckouts(), 0L);
    assertEquals(stats.getNumFailedCheckouts(), 0L);

    assertEquals(stats.getNumReleasedValid(), 0L);


    assertEquals(stats.getNumSuccessfulConnectionAttempts(), 0L);
    stats.incrementNumSuccessfulConnectionAttempts();
    assertEquals(stats.getNumSuccessfulConnectionAttempts(), 1L);

    assertEquals(stats.getNumFailedConnectionAttempts(), 0L);
    stats.incrementNumFailedConnectionAttempts();
    assertEquals(stats.getNumFailedConnectionAttempts(), 1L);

    assertEquals(stats.getNumConnectionsClosedDefunct(), 0L);
    stats.incrementNumConnectionsClosedDefunct();
    assertEquals(stats.getNumConnectionsClosedDefunct(), 1L);

    assertEquals(stats.getNumConnectionsClosedExpired(), 0L);
    stats.incrementNumConnectionsClosedExpired();
    assertEquals(stats.getNumConnectionsClosedExpired(), 1L);

    assertEquals(stats.getNumConnectionsClosedUnneeded(), 0L);
    stats.incrementNumConnectionsClosedUnneeded();
    assertEquals(stats.getNumConnectionsClosedUnneeded(), 1L);

    assertEquals(stats.getNumSuccessfulCheckouts(), 0L);
    stats.incrementNumSuccessfulCheckoutsWithoutWaiting();
    assertEquals(stats.getNumSuccessfulCheckouts(), 1L);
    assertEquals(stats.getNumSuccessfulCheckoutsWithoutWaiting(), 1L);
    stats.incrementNumSuccessfulCheckoutsAfterWaiting();
    assertEquals(stats.getNumSuccessfulCheckouts(), 2L);
    assertEquals(stats.getNumSuccessfulCheckoutsAfterWaiting(), 1L);
    stats.incrementNumSuccessfulCheckoutsNewConnection();
    assertEquals(stats.getNumSuccessfulCheckouts(), 3L);
    assertEquals(stats.getNumSuccessfulCheckoutsNewConnection(), 1L);

    assertEquals(stats.getNumFailedCheckouts(), 0L);
    stats.incrementNumFailedCheckouts();
    assertEquals(stats.getNumFailedCheckouts(), 1L);

    assertEquals(stats.getNumReleasedValid(), 0L);
    stats.incrementNumReleasedValid();
    assertEquals(stats.getNumReleasedValid(), 1L);


    stats.reset();


    assertEquals(stats.getNumSuccessfulConnectionAttempts(), 0L);
    assertEquals(stats.getNumFailedConnectionAttempts(), 0L);

    assertEquals(stats.getNumConnectionsClosedDefunct(), 0L);
    assertEquals(stats.getNumConnectionsClosedExpired(), 0L);
    assertEquals(stats.getNumConnectionsClosedUnneeded(), 0L);

    assertEquals(stats.getNumSuccessfulCheckouts(), 0L);
    assertEquals(stats.getNumFailedCheckouts(), 0L);

    assertEquals(stats.getNumReleasedValid(), 0L);
  }



  /**
   * Tests to ensure that statistics are properly maintained for a number of
   * uses within the connection pool.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneralPoolStatistics()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());

    LDAPConnectionPool pool = new LDAPConnectionPool(conn, 1, 2);
    pool.setCreateIfNecessary(true);
    pool.setMaxWaitTimeMillis(0L);

    LDAPConnectionPoolStatistics stats = pool.getConnectionPoolStatistics();

    assertNotNull(stats.toString());

    // The original connection will be used in the pool, so no connections will
    // have been created or checked out by this point yet.  There should be one
    // connection available.
    assertEquals(stats.getNumSuccessfulConnectionAttempts(), 0L);
    assertEquals(stats.getNumSuccessfulCheckouts(), 0L);
    assertEquals(stats.getNumAvailableConnections(), 1L);
    assertEquals(stats.getMaximumAvailableConnections(), 2L);

    // Attempt to get four connections.  This will cause three new connections
    // to be created, and there will be four checkouts.
    LDAPConnection c1 = pool.getConnection();
    LDAPConnection c2 = pool.getConnection();
    LDAPConnection c3 = pool.getConnection();
    LDAPConnection c4 = pool.getConnection();

    assertEquals(stats.getNumSuccessfulConnectionAttempts(), 3L);
    assertEquals(stats.getNumSuccessfulCheckouts(), 4L);
    assertEquals(stats.getNumAvailableConnections(), 0L);
    assertEquals(stats.getMaximumAvailableConnections(), 2L);

    // Release three connections normally, and one as defunct.  This should
    // cause two releases, one closed as unneeded, and one closed defunct.
    pool.releaseConnection(c1);
    pool.releaseConnection(c2);
    pool.releaseConnection(c3);
    pool.releaseDefunctConnection(c4);

    assertEquals(stats.getNumReleasedValid(), 2L);
    assertEquals(stats.getNumConnectionsClosedUnneeded(), 1L);
    assertEquals(stats.getNumConnectionsClosedDefunct(), 1L);
    assertEquals(stats.getNumAvailableConnections(), 2L);
    assertEquals(stats.getMaximumAvailableConnections(), 2L);


    // Update the pool to set an expiration time for the connections and
    // make sure that connections will be expired appropriately.
    assertEquals(pool.getMaxConnectionAgeMillis(), 0L);
    assertEquals(stats.getNumConnectionsClosedExpired(), 0L);
    assertFalse(pool.checkConnectionAgeOnRelease());
    pool.setMaxConnectionAgeMillis(500L);
    pool.setCheckConnectionAgeOnRelease(true);
    c1 = pool.getConnection();
    c2 = pool.getConnection();
    Thread.sleep(1000L);
    pool.releaseConnection(c1);
    pool.releaseConnection(c2);
    assertEquals(stats.getNumConnectionsClosedExpired(), 2L);
    pool.setMaxConnectionAgeMillis(0L);
    pool.setCheckConnectionAgeOnRelease(false);


    // Update the pool to set an expiration time for just connections created
    // to replace defunct connections, and make sure that defunct connections
    // will be expired appropriately.
    assertEquals(pool.getMaxConnectionAgeMillis(), 0L);
    assertNull(pool.getMaxDefunctReplacementConnectionAgeMillis());
    assertEquals(stats.getNumConnectionsClosedExpired(), 2L);
    assertFalse(pool.checkConnectionAgeOnRelease());
    pool.setMaxDefunctReplacementConnectionAgeMillis(500L);
    assertEquals(pool.getMaxDefunctReplacementConnectionAgeMillis(),
         Long.valueOf(500L));
    pool.setCheckConnectionAgeOnRelease(true);
    c1 = pool.getConnection();
    c2 = pool.getConnection();
    pool.releaseConnection(c1);
    pool.releaseDefunctConnection(c2);
    Thread.sleep(1000L);
    c1 = pool.getConnection();
    c2 = pool.getConnection();
    pool.releaseConnection(c1);
    pool.releaseConnection(c2);
    assertEquals(stats.getNumConnectionsClosedExpired(), 3L);
    pool.setMaxDefunctReplacementConnectionAgeMillis(-1L);
    assertEquals(pool.getMaxDefunctReplacementConnectionAgeMillis(),
         Long.valueOf(0L));
    pool.setMaxDefunctReplacementConnectionAgeMillis(null);
    assertNull(pool.getMaxDefunctReplacementConnectionAgeMillis());
    pool.setCheckConnectionAgeOnRelease(false);


    pool.close();

    assertNotNull(stats.toString());
  }
}
