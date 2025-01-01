/*
 * Copyright 2024-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024-2025 Ping Identity Corporation
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
 * Copyright (C) 2024-2025 Ping Identity Corporation
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



import java.util.concurrent.TimeUnit;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;



/**
 * This class provides a set of test cases that verify the behavior of the
 * maximum idle duration LDAP connection pool health check.
 */
public final class MaximumIdleDurationLDAPConnectionPoolHealthCheckTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the health check for connections that should not be considered idle.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectionsNotIdle()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());
    try (LDAPConnectionPool pool = new LDAPConnectionPool(serverSet, null, 1))
    {
      final MaximumIdleDurationLDAPConnectionPoolHealthCheck healthCheck =
           new MaximumIdleDurationLDAPConnectionPoolHealthCheck(1,
                TimeUnit.HOURS);
      assertEquals(healthCheck.getMaximumIdleDurationMillis(), 3_600_000L);
      assertEquals(healthCheck.getIdleConnectionCount(), 0L);
      assertNotNull(healthCheck.toString());

      pool.setHealthCheck(healthCheck);
      pool.setHealthCheckIntervalMillis(100L);

      Thread.sleep(1000L);

      assertEquals(healthCheck.getIdleConnectionCount(), 0L);

      assertNotNull(pool.getRootDSE());

      Thread.sleep(1000L);

      assertEquals(healthCheck.getMaximumIdleDurationMillis(), 3_600_000L);
      assertEquals(healthCheck.getIdleConnectionCount(), 0L);
      assertNotNull(healthCheck.toString());
    }
  }



  /**
   * Tests the health check for connections that should be considered idle.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectionsIdle()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());
    try (LDAPConnectionPool pool = new LDAPConnectionPool(serverSet, null, 1))
    {
      final MaximumIdleDurationLDAPConnectionPoolHealthCheck healthCheck =
           new MaximumIdleDurationLDAPConnectionPoolHealthCheck(100L);
      assertEquals(healthCheck.getMaximumIdleDurationMillis(), 100L);
      assertEquals(healthCheck.getIdleConnectionCount(), 0L);
      assertNotNull(healthCheck.toString());

      pool.setHealthCheck(healthCheck);
      pool.setHealthCheckIntervalMillis(100L);

      Thread.sleep(1000L);

      assertTrue(healthCheck.getIdleConnectionCount() > 0L);
    }
  }
}
