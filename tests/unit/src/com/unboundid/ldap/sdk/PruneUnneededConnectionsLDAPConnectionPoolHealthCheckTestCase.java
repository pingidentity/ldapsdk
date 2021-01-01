/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;



/**
 * This class provides a set of test cases for the prune unneeded connections
 * LDAP connection pool health check.
 */
public final class PruneUnneededConnectionsLDAPConnectionPoolHealthCheckTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the health check when it is configured with the
   * minimum number of available connections set to zero, and the minimum length
   * of time set to zero milliseconds.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutMinimumAndWithoutDelay()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final LDAPConnectionPool pool = ds.getConnectionPool(null, null, 10, 10);
    assertEquals(pool.getCurrentAvailableConnections(), 10);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    final PruneUnneededConnectionsLDAPConnectionPoolHealthCheck healthCheck =
         new PruneUnneededConnectionsLDAPConnectionPoolHealthCheck(0, 0L);
    assertEquals(healthCheck.getMinAvailableConnections(), 0);
    assertEquals(
         healthCheck.getMinDurationMillisExceedingMinAvailableConnections(),
         0L);
    assertNotNull(healthCheck.toString());

    healthCheck.performPoolMaintenance(pool);

    assertEquals(pool.getCurrentAvailableConnections(), 0);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    pool.close();
  }



  /**
   * Tests the behavior of the health check when it is configured with nonzero
   * values for the minimum number of available connections and the delay before
   * closing connections.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithMinimumAndWithDelay()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final LDAPConnectionPool pool = ds.getConnectionPool(null, null, 10, 10);
    assertEquals(pool.getCurrentAvailableConnections(), 10);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    final PruneUnneededConnectionsLDAPConnectionPoolHealthCheck healthCheck =
         new PruneUnneededConnectionsLDAPConnectionPoolHealthCheck(5, 100L);
    assertEquals(healthCheck.getMinAvailableConnections(), 5);
    assertEquals(
         healthCheck.getMinDurationMillisExceedingMinAvailableConnections(),
         100L);
    assertNotNull(healthCheck.toString());

    healthCheck.performPoolMaintenance(pool);

    assertEquals(pool.getCurrentAvailableConnections(), 10);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    final LinkedList<LDAPConnection> checkedOutConnections = new LinkedList<>();
    for (int i=1; i <= 10; i++)
    {
      checkedOutConnections.add(pool.getConnection());
      assertEquals(pool.getCurrentAvailableConnections(), (10 - i));
      assertEquals(pool.getMaximumAvailableConnections(), 10);
    }

    healthCheck.performPoolMaintenance(pool);

    assertEquals(pool.getCurrentAvailableConnections(), 0);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    for (int i=1; i <= 5; i++)
    {
      final LDAPConnection conn = checkedOutConnections.removeFirst();
      pool.releaseConnection(conn);

      assertEquals(pool.getCurrentAvailableConnections(), i);
      assertEquals(pool.getMaximumAvailableConnections(), 10);

      healthCheck.performPoolMaintenance(pool);

      assertEquals(pool.getCurrentAvailableConnections(), i);
      assertEquals(pool.getMaximumAvailableConnections(), 10);
    }

    for (int i=6; i <= 10; i++)
    {
      final LDAPConnection conn = checkedOutConnections.removeFirst();
      pool.releaseConnection(conn);

      assertEquals(pool.getCurrentAvailableConnections(), i);
      assertEquals(pool.getMaximumAvailableConnections(), 10);
    }

    healthCheck.performPoolMaintenance(pool);

    assertEquals(pool.getCurrentAvailableConnections(), 10);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    final long stopWaitingTime = System.currentTimeMillis() + 101L;
    while (System.currentTimeMillis() <= stopWaitingTime)
    {
      healthCheck.performPoolMaintenance(pool);
      Thread.sleep(1L);
    }

    assertEquals(pool.getCurrentAvailableConnections(), 5);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    pool.close();
  }



  /**
   * Tests the behavior of the health check when it is called for a connection
   * pool other than an {@code LDAPConnectionPool}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithInvalidPoolType()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final LDAPThreadLocalConnectionPool pool =
         new LDAPThreadLocalConnectionPool(ds.getConnection());

    final PruneUnneededConnectionsLDAPConnectionPoolHealthCheck healthCheck =
         new PruneUnneededConnectionsLDAPConnectionPoolHealthCheck(0, 0L);
    assertEquals(healthCheck.getMinAvailableConnections(), 0);
    assertEquals(
         healthCheck.getMinDurationMillisExceedingMinAvailableConnections(),
         0L);
    assertNotNull(healthCheck.toString());

    healthCheck.performPoolMaintenance(pool);

    pool.close();
  }
}
