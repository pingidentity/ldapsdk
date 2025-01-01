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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.concurrent.TimeUnit;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of unit tests for the replication backlog LDAP
 * connection pool health check.
 */
public final class ReplicationBacklogLDAPConnectionPoolHealthCheckTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when the monitor entry exists and the current backlog is
   * within the specified count limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBacklogWithinCountLimit()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds =
              getDS(1234L, TimeUnit.HOURS.toMillis(2L));
         final LDAPConnection conn = ds.getConnection())
    {
      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, true,
                true, true, true, true, 0L, "dc=example,dc=com",
                1234567L, null);

      assertTrue(healthCheck.invokeOnCreate());
      assertTrue(healthCheck.invokeAfterAuthentication());
      assertTrue(healthCheck.invokeOnCheckout());
      assertTrue(healthCheck.invokeOnRelease());
      assertTrue(healthCheck.invokeForBackgroundChecks());
      assertTrue(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertNotNull(healthCheck.getBaseDN());
      assertDNsEqual(healthCheck.getBaseDN(), "dc=example,dc=com");

      assertNotNull(healthCheck.getMaxAllowedBacklogCount());
      assertEquals(healthCheck.getMaxAllowedBacklogCount().longValue(),
           1234567L);

      assertNull(healthCheck.getMaxAllowedBacklogAgeMillis());

      assertNotNull(healthCheck.toString());

      healthCheck.ensureNewConnectionValid(conn);
      healthCheck.ensureConnectionValidAfterAuthentication(conn,
           new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
      healthCheck.ensureConnectionValidForCheckout(conn);
      healthCheck.ensureConnectionValidForRelease(conn);
      healthCheck.ensureConnectionValidForContinuedUse(conn);
      healthCheck.ensureConnectionValidAfterException(conn,
           new LDAPException(ResultCode.UNAVAILABLE));
    }
  }



  /**
   * Tests the behavior when the monitor entry exists and the current backlog
   * exceeds the specified count limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBacklogExceedsCountLimit()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(12345678L, 123456L);
         final LDAPConnection conn = ds.getConnection())
    {
      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, false,
                false, false, false, false, 1_234L, "dc=example,dc=com",
                1234567L, TimeUnit.HOURS.toMillis(6L));

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 1_234L);

      assertNotNull(healthCheck.getBaseDN());
      assertDNsEqual(healthCheck.getBaseDN(), "dc=example,dc=com");

      assertNotNull(healthCheck.getMaxAllowedBacklogCount());
      assertEquals(healthCheck.getMaxAllowedBacklogCount().longValue(),
           1234567L);

      assertNotNull(healthCheck.getMaxAllowedBacklogAgeMillis());
      assertEquals(healthCheck.getMaxAllowedBacklogAgeMillis().longValue(),
           TimeUnit.HOURS.toMillis(6L));

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception when validating a newly created " +
             "connection when the current backlog count exceeds the maximum " +
             "allowed value.");
      }
      catch (final LDAPException e)
      {
        // This was expected.
      }

      healthCheck.ensureConnectionValidAfterAuthentication(conn,
           new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
      healthCheck.ensureConnectionValidForCheckout(conn);
      healthCheck.ensureConnectionValidForRelease(conn);
      healthCheck.ensureConnectionValidForContinuedUse(conn);
      healthCheck.ensureConnectionValidAfterException(conn,
           new LDAPException(ResultCode.UNAVAILABLE));
    }
  }



  /**
   * Tests the behavior when the monitor entry exists, but does not specify the
   * current backlog count.  In this case, it will be assumed that the backlog
   * count is within the acceptable range.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBacklogCountMissingFromMonitorEntry()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds =
              getDS(null, TimeUnit.HOURS.toMillis(2L));
         final LDAPConnection conn = ds.getConnection())
    {
      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, true,
                true, true, true, true, 0L, "dc=example,dc=com",
                1234567L, null);

      assertTrue(healthCheck.invokeOnCreate());
      assertTrue(healthCheck.invokeAfterAuthentication());
      assertTrue(healthCheck.invokeOnCheckout());
      assertTrue(healthCheck.invokeOnRelease());
      assertTrue(healthCheck.invokeForBackgroundChecks());
      assertTrue(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertNotNull(healthCheck.getBaseDN());
      assertDNsEqual(healthCheck.getBaseDN(), "dc=example,dc=com");

      assertNotNull(healthCheck.getMaxAllowedBacklogCount());
      assertEquals(healthCheck.getMaxAllowedBacklogCount().longValue(),
           1234567L);

      assertNull(healthCheck.getMaxAllowedBacklogAgeMillis());

      assertNotNull(healthCheck.toString());

      healthCheck.ensureNewConnectionValid(conn);
      healthCheck.ensureConnectionValidAfterAuthentication(conn,
           new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
      healthCheck.ensureConnectionValidForCheckout(conn);
      healthCheck.ensureConnectionValidForRelease(conn);
      healthCheck.ensureConnectionValidForContinuedUse(conn);
      healthCheck.ensureConnectionValidAfterException(conn,
           new LDAPException(ResultCode.UNAVAILABLE));
    }
  }



  /**
   * Tests the behavior when the monitor entry exists and the oldest change in
   * the backlog is within the specified age limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBacklogWithinAgeLimit()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds =
              getDS(1234L, TimeUnit.HOURS.toMillis(2L));
         final LDAPConnection conn = ds.getConnection())
    {
      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, true,
                true, true, true, true, 0L, "dc=example,dc=com",
                null, TimeUnit.HOURS.toMillis(6L));

      assertTrue(healthCheck.invokeOnCreate());
      assertTrue(healthCheck.invokeAfterAuthentication());
      assertTrue(healthCheck.invokeOnCheckout());
      assertTrue(healthCheck.invokeOnRelease());
      assertTrue(healthCheck.invokeForBackgroundChecks());
      assertTrue(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertNotNull(healthCheck.getBaseDN());
      assertDNsEqual(healthCheck.getBaseDN(), "dc=example,dc=com");

      assertNull(healthCheck.getMaxAllowedBacklogCount());

      assertNotNull(healthCheck.getMaxAllowedBacklogAgeMillis());
      assertEquals(healthCheck.getMaxAllowedBacklogAgeMillis().longValue(),
           TimeUnit.HOURS.toMillis(6L));

      assertNotNull(healthCheck.toString());

      healthCheck.ensureNewConnectionValid(conn);
      healthCheck.ensureConnectionValidAfterAuthentication(conn,
           new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
      healthCheck.ensureConnectionValidForCheckout(conn);
      healthCheck.ensureConnectionValidForRelease(conn);
      healthCheck.ensureConnectionValidForContinuedUse(conn);
      healthCheck.ensureConnectionValidAfterException(conn,
           new LDAPException(ResultCode.UNAVAILABLE));
    }
  }



  /**
   * Tests the behavior when the monitor entry exists and the oldest change in
   * the backlog exceeds the specified age limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBacklogExceedsAgeLimit()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds =
              getDS(1234L, TimeUnit.HOURS.toMillis(24L));
         final LDAPConnection conn = ds.getConnection())
    {
      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, false,
                false, false, false, false, 1_234L, "dc=example,dc=com",
                1234567L, TimeUnit.HOURS.toMillis(6L));

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 1_234L);

      assertNotNull(healthCheck.getBaseDN());
      assertDNsEqual(healthCheck.getBaseDN(), "dc=example,dc=com");

      assertNotNull(healthCheck.getMaxAllowedBacklogCount());
      assertEquals(healthCheck.getMaxAllowedBacklogCount().longValue(),
           1234567L);

      assertNotNull(healthCheck.getMaxAllowedBacklogAgeMillis());
      assertEquals(healthCheck.getMaxAllowedBacklogAgeMillis().longValue(),
           TimeUnit.HOURS.toMillis(6L));

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception when validating a newly created " +
             "connection when the current backlog age exceeds the maximum " +
             "allowed value.");
      }
      catch (final LDAPException e)
      {
        // This was expected.
      }

      healthCheck.ensureConnectionValidAfterAuthentication(conn,
           new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
      healthCheck.ensureConnectionValidForCheckout(conn);
      healthCheck.ensureConnectionValidForRelease(conn);
      healthCheck.ensureConnectionValidForContinuedUse(conn);
      healthCheck.ensureConnectionValidAfterException(conn,
           new LDAPException(ResultCode.UNAVAILABLE));
    }
  }



  /**
   * Tests the behavior when the monitor entry exists, but does not specify the
   * oldest change in the backlog.  In this case, it will be assumed that the
   * backlog age is within the acceptable range.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBacklogAgeMissingFromMonitorEntry()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(1234L, null);
         final LDAPConnection conn = ds.getConnection())
    {
      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, true,
                true, true, true, true, 0L, "dc=example,dc=com",
                null, TimeUnit.HOURS.toMillis(6L));

      assertTrue(healthCheck.invokeOnCreate());
      assertTrue(healthCheck.invokeAfterAuthentication());
      assertTrue(healthCheck.invokeOnCheckout());
      assertTrue(healthCheck.invokeOnRelease());
      assertTrue(healthCheck.invokeForBackgroundChecks());
      assertTrue(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertNotNull(healthCheck.getBaseDN());
      assertDNsEqual(healthCheck.getBaseDN(), "dc=example,dc=com");

      assertNull(healthCheck.getMaxAllowedBacklogCount());

      assertNotNull(healthCheck.getMaxAllowedBacklogAgeMillis());
      assertEquals(healthCheck.getMaxAllowedBacklogAgeMillis().longValue(),
           TimeUnit.HOURS.toMillis(6L));

      assertNotNull(healthCheck.toString());

      healthCheck.ensureNewConnectionValid(conn);
      healthCheck.ensureConnectionValidAfterAuthentication(conn,
           new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
      healthCheck.ensureConnectionValidForCheckout(conn);
      healthCheck.ensureConnectionValidForRelease(conn);
      healthCheck.ensureConnectionValidForContinuedUse(conn);
      healthCheck.ensureConnectionValidAfterException(conn,
           new LDAPException(ResultCode.UNAVAILABLE));
    }
  }



  /**
   * Tests the behavior when the monitor entry does not exist.  In this case,
   * the health check will assume that the replication backlog is acceptable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingMonitorEntry()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(1234L, 123456L);
         final LDAPConnection conn = ds.getConnection())
    {
      conn.delete("cn=Replica dc_example_dc_com,cn=monitor");

      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, true,
                true, true, true, true, 0L, "dc=example,dc=com",
                1234567L, TimeUnit.HOURS.toMillis(6L));

      assertTrue(healthCheck.invokeOnCreate());
      assertTrue(healthCheck.invokeAfterAuthentication());
      assertTrue(healthCheck.invokeOnCheckout());
      assertTrue(healthCheck.invokeOnRelease());
      assertTrue(healthCheck.invokeForBackgroundChecks());
      assertTrue(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertNotNull(healthCheck.getBaseDN());
      assertDNsEqual(healthCheck.getBaseDN(), "dc=example,dc=com");

      assertNotNull(healthCheck.getMaxAllowedBacklogCount());
      assertEquals(healthCheck.getMaxAllowedBacklogCount().longValue(),
           1234567L);

      assertNotNull(healthCheck.getMaxAllowedBacklogAgeMillis());
      assertEquals(healthCheck.getMaxAllowedBacklogAgeMillis().longValue(),
           TimeUnit.HOURS.toMillis(6L));

      assertNotNull(healthCheck.toString());

      healthCheck.ensureNewConnectionValid(conn);
      healthCheck.ensureConnectionValidAfterAuthentication(conn,
           new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
      healthCheck.ensureConnectionValidForCheckout(conn);
      healthCheck.ensureConnectionValidForRelease(conn);
      healthCheck.ensureConnectionValidForContinuedUse(conn);
      healthCheck.ensureConnectionValidAfterException(conn,
           new LDAPException(ResultCode.UNAVAILABLE));
    }
  }



  /**
   * Tests the behavior when an error occurs while attempting to retrieve the
   * monitor entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testErrorRetrievingMonitorEntry()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(1234L, 123456L);
         final LDAPConnection conn = ds.getConnection())
    {
      conn.close(StaticUtils.NO_CONTROLS);

      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, false,
                false, false, false, false, 1_234L, "dc=example,dc=com",
                1234567L, TimeUnit.HOURS.toMillis(6L));

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 1_234L);

      assertNotNull(healthCheck.getBaseDN());
      assertDNsEqual(healthCheck.getBaseDN(), "dc=example,dc=com");

      assertNotNull(healthCheck.getMaxAllowedBacklogCount());
      assertEquals(healthCheck.getMaxAllowedBacklogCount().longValue(),
           1234567L);

      assertNotNull(healthCheck.getMaxAllowedBacklogAgeMillis());
      assertEquals(healthCheck.getMaxAllowedBacklogAgeMillis().longValue(),
           TimeUnit.HOURS.toMillis(6L));

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception when validating a newly created " +
             "connection when an error occurs while trying to retrieve the " +
             "monitor entry.");
      }
      catch (final LDAPException e)
      {
        // This was expected.
      }

      healthCheck.ensureConnectionValidAfterAuthentication(conn,
           new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
      healthCheck.ensureConnectionValidForCheckout(conn);
      healthCheck.ensureConnectionValidForRelease(conn);
      healthCheck.ensureConnectionValidForContinuedUse(conn);
      healthCheck.ensureConnectionValidAfterException(conn,
           new LDAPException(ResultCode.UNAVAILABLE));
    }
  }



  /**
   * Tests the behavior when trying to create an instance of the health check
   * without specifying either a maximum backlog count or age.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHealthCheckWithoutEitherCountOrAge()
         throws Exception
  {
    try
    {
      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, true,
                true, true, true, true, 0L, "dc=example,dc=com",
                null, null);
      fail("Expected an exception when trying to create the health check " +
           "without a maximum count or age.");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to create an instance of the health check
   * with a negative maximum count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHealthCheckWithoutNegativeCount()
         throws Exception
  {
    try
    {
      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, true,
                true, true, true, true, 0L, "dc=example,dc=com",
                -1L, null);
      fail("Expected an exception when trying to create the health check " +
           "with a negative count.");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to create an instance of the health check
   * with a negative maximum age.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHealthCheckWithoutNegativeAge()
         throws Exception
  {
    try
    {
      final ReplicationBacklogLDAPConnectionPoolHealthCheck healthCheck =
           new ReplicationBacklogLDAPConnectionPoolHealthCheck(true, true,
                true, true, true, true, 0L, "dc=example,dc=com",
                null, -1L);
      fail("Expected an exception when trying to create the health check " +
           "with a negative age.");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Retrieves an in-memory directory server instance that contains a replica
   * monitor entry for the "dc=example,dc=com" replication domain with the
   * specified count and age values.
   *
   * @param  currentCount      The number of changes currently in the backlog.
   *                           It may be {@code null} if the current count
   *                           should not be included.
   * @param  currentAgeMillis  The age of the oldest change currently in the
   *                           backlog, in milliseconds.  It may be {@code null}
   *                           the current age should not be included.
   *
   * @return  The in-memory directory server instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private InMemoryDirectoryServer getDS(final Long currentCount,
                                        final Long currentAgeMillis)
          throws Exception
  {
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("cn=monitor");
    dsConfig.setSchema(null);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsConfig);
    ds.add(
         "dn: cn=monitor",
         "objectClass: top",
         "objectClass: ds-general-monitor-entry",
         "cn: monitor");

    final Entry replicaMonitorEntry = new Entry(
         "dn: cn=Replica dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replica-monitor-entry",
         "cn: Replica dc_example_dc_com",
         "base-dn: dc=example,dc=com");

    if (currentCount != null)
    {
      replicaMonitorEntry.addAttribute("replication-backlog",
           String.valueOf(currentCount));
    }

    if (currentAgeMillis != null)
    {
      final long oldestChangeTime =
           System.currentTimeMillis() - currentAgeMillis;
      replicaMonitorEntry.addAttribute("age-of-oldest-backlog-change",
           StaticUtils.encodeGeneralizedTime(oldestChangeTime));
    }

    ds.add(replicaMonitorEntry);

    ds.startListening();
    return ds;
  }
}
