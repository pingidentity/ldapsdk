/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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



import java.util.Set;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of unit tests for the active alerts LDAP connection
 * pool health check.
 */
public final class ActiveAlertsLDAPConnectionPoolHealthCheckTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when the monitor entry exists, can be successfully
   * retrieved, and does not include any active alert types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoActiveAlerts()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(null, null);
         final LDAPConnection conn = ds.getConnection())
    {
      final ActiveAlertsLDAPConnectionPoolHealthCheck healthCheck =
           new ActiveAlertsLDAPConnectionPoolHealthCheck(true, true, true, true,
                true, true, 0L, false, null, null);

      assertTrue(healthCheck.invokeOnCreate());
      assertTrue(healthCheck.invokeAfterAuthentication());
      assertTrue(healthCheck.invokeOnCheckout());
      assertTrue(healthCheck.invokeOnRelease());
      assertTrue(healthCheck.invokeForBackgroundChecks());
      assertTrue(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertFalse(healthCheck.ignoreAllDegradedAlertTypes());

      assertNotNull(healthCheck.getIgnoredDegradedAlertTypes());
      assertTrue(healthCheck.getIgnoredDegradedAlertTypes().isEmpty());

      assertNotNull(healthCheck.getIgnoredUnavailableAlertTypes());
      assertTrue(healthCheck.getIgnoredUnavailableAlertTypes().isEmpty());

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
   * Tests the behavior when the monitor entry exists, can be successfully
   * retrieved, and has degraded alert types when none are ignored.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDegradedAlertTypesNoneIgnored()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(
              StaticUtils.setOf("test-degraded-alert-type"),
              null);
         final LDAPConnection conn = ds.getConnection())
    {
      final ActiveAlertsLDAPConnectionPoolHealthCheck healthCheck =
           new ActiveAlertsLDAPConnectionPoolHealthCheck(true, false, false,
                false, false, false, 1234L, false, null, null);

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 1_234L);

      assertFalse(healthCheck.ignoreAllDegradedAlertTypes());

      assertNotNull(healthCheck.getIgnoredDegradedAlertTypes());
      assertTrue(healthCheck.getIgnoredDegradedAlertTypes().isEmpty());

      assertNotNull(healthCheck.getIgnoredUnavailableAlertTypes());
      assertTrue(healthCheck.getIgnoredUnavailableAlertTypes().isEmpty());

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception because of a non-ignored degraded alert " +
             "type.");
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
   * Tests the behavior when the monitor entry exists, can be successfully
   * retrieved, and has degraded alert types when all are ignored.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDegradedAlertTypesAllIgnored()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(
              StaticUtils.setOf("test-degraded-alert-type"),
              null);
         final LDAPConnection conn = ds.getConnection())
    {
      final ActiveAlertsLDAPConnectionPoolHealthCheck healthCheck =
           new ActiveAlertsLDAPConnectionPoolHealthCheck(true, true, true, true,
                true, true, 0L, true, null, null);

      assertTrue(healthCheck.invokeOnCreate());
      assertTrue(healthCheck.invokeAfterAuthentication());
      assertTrue(healthCheck.invokeOnCheckout());
      assertTrue(healthCheck.invokeOnRelease());
      assertTrue(healthCheck.invokeForBackgroundChecks());
      assertTrue(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertTrue(healthCheck.ignoreAllDegradedAlertTypes());

      assertNotNull(healthCheck.getIgnoredDegradedAlertTypes());
      assertTrue(healthCheck.getIgnoredDegradedAlertTypes().isEmpty());

      assertNotNull(healthCheck.getIgnoredUnavailableAlertTypes());
      assertTrue(healthCheck.getIgnoredUnavailableAlertTypes().isEmpty());

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
   * Tests the behavior when the monitor entry exists, can be successfully
   * retrieved, and has degraded alert types when a specific set of degraded
   * alert types are ignored, including one that is active.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDegradedAlertTypesSomeIgnoredIncludingActive()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(
              StaticUtils.setOf("test-degraded-alert-type-1"),
              null);
         final LDAPConnection conn = ds.getConnection())
    {
      final ActiveAlertsLDAPConnectionPoolHealthCheck healthCheck =
           new ActiveAlertsLDAPConnectionPoolHealthCheck(true, true, true, true,
                true, true, 0L, false,
                StaticUtils.setOf(
                     "test-degraded-alert-type-1",
                     "test-degraded-alert-type-2"),
                null);

      assertTrue(healthCheck.invokeOnCreate());
      assertTrue(healthCheck.invokeAfterAuthentication());
      assertTrue(healthCheck.invokeOnCheckout());
      assertTrue(healthCheck.invokeOnRelease());
      assertTrue(healthCheck.invokeForBackgroundChecks());
      assertTrue(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertFalse(healthCheck.ignoreAllDegradedAlertTypes());

      assertNotNull(healthCheck.getIgnoredDegradedAlertTypes());
      assertFalse(healthCheck.getIgnoredDegradedAlertTypes().isEmpty());
      assertEquals(healthCheck.getIgnoredDegradedAlertTypes(),
           StaticUtils.setOf("test-degraded-alert-type-1",
                "test-degraded-alert-type-2"));

      assertNotNull(healthCheck.getIgnoredUnavailableAlertTypes());
      assertTrue(healthCheck.getIgnoredUnavailableAlertTypes().isEmpty());

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
   * Tests the behavior when the monitor entry exists, can be successfully
   * retrieved, and has degraded alert types when a specific set of degraded
   * alert types are ignored, but not including one that is active.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDegradedAlertTypesSomeIgnoredNotIncludingActive()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(
              StaticUtils.setOf("test-degraded-alert-type-3"),
              null);
         final LDAPConnection conn = ds.getConnection())
    {
      final ActiveAlertsLDAPConnectionPoolHealthCheck healthCheck =
           new ActiveAlertsLDAPConnectionPoolHealthCheck(true, false, false,
                false, false, false, 0L, false,
                StaticUtils.setOf(
                     "test-degraded-alert-type-1",
                     "test-degraded-alert-type-2"),
                null);

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertFalse(healthCheck.ignoreAllDegradedAlertTypes());

      assertNotNull(healthCheck.getIgnoredDegradedAlertTypes());
      assertFalse(healthCheck.getIgnoredDegradedAlertTypes().isEmpty());
      assertEquals(healthCheck.getIgnoredDegradedAlertTypes(),
           StaticUtils.setOf("test-degraded-alert-type-1",
                "test-degraded-alert-type-2"));

      assertNotNull(healthCheck.getIgnoredUnavailableAlertTypes());
      assertTrue(healthCheck.getIgnoredUnavailableAlertTypes().isEmpty());

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception because of a non-ignored degraded alert " +
             "type.");
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
   * Tests the behavior when the monitor entry exists, can be successfully
   * retrieved, and has unavailable alert types when none are ignored.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnavailableAlertTypesNoneIgnored()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(null,
              StaticUtils.setOf("test-unavailable-alert-type"));
         final LDAPConnection conn = ds.getConnection())
    {
      final ActiveAlertsLDAPConnectionPoolHealthCheck healthCheck =
           new ActiveAlertsLDAPConnectionPoolHealthCheck(true, false, false,
                false, false, false, 1234L, false, null, null);

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 1_234L);

      assertFalse(healthCheck.ignoreAllDegradedAlertTypes());

      assertNotNull(healthCheck.getIgnoredDegradedAlertTypes());
      assertTrue(healthCheck.getIgnoredDegradedAlertTypes().isEmpty());

      assertNotNull(healthCheck.getIgnoredUnavailableAlertTypes());
      assertTrue(healthCheck.getIgnoredUnavailableAlertTypes().isEmpty());

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception because of a non-ignored unavailable " +
             "alert type.");
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
   * Tests the behavior when the monitor entry exists, can be successfully
   * retrieved, and has unavailable alert types when a specific set of
   * unavailable alert types are ignored, including one that is active.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnavailableAlertTypesSomeIgnoredIncludingActive()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(null,
              StaticUtils.setOf("test-unavailable-alert-type-1"));
         final LDAPConnection conn = ds.getConnection())
    {
      final ActiveAlertsLDAPConnectionPoolHealthCheck healthCheck =
           new ActiveAlertsLDAPConnectionPoolHealthCheck(true, true, true, true,
                true, true, 0L, false, null,
                StaticUtils.setOf(
                     "test-unavailable-alert-type-1",
                     "test-unavailable-alert-type-2"));

      assertTrue(healthCheck.invokeOnCreate());
      assertTrue(healthCheck.invokeAfterAuthentication());
      assertTrue(healthCheck.invokeOnCheckout());
      assertTrue(healthCheck.invokeOnRelease());
      assertTrue(healthCheck.invokeForBackgroundChecks());
      assertTrue(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertFalse(healthCheck.ignoreAllDegradedAlertTypes());

      assertNotNull(healthCheck.getIgnoredDegradedAlertTypes());
      assertTrue(healthCheck.getIgnoredDegradedAlertTypes().isEmpty());

      assertNotNull(healthCheck.getIgnoredUnavailableAlertTypes());
      assertFalse(healthCheck.getIgnoredUnavailableAlertTypes().isEmpty());
      assertEquals(healthCheck.getIgnoredUnavailableAlertTypes(),
           StaticUtils.setOf("test-unavailable-alert-type-1",
                "test-unavailable-alert-type-2"));

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
   * Tests the behavior when the monitor entry exists, can be successfully
   * retrieved, and has unavailable alert types when a specific set of
   * unavailable alert types are ignored, but not including one that is active.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnavailableAlertTypesSomeIgnoredNotIncludingActive()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(null,
              StaticUtils.setOf("test-unavailable-alert-type-3"));
         final LDAPConnection conn = ds.getConnection())
    {
      final ActiveAlertsLDAPConnectionPoolHealthCheck healthCheck =
           new ActiveAlertsLDAPConnectionPoolHealthCheck(true, false, false,
                false, false, false, 0L, false, null,
                StaticUtils.setOf(
                     "test-unavailable-alert-type-1",
                     "test-unavailable-alert-type-2"));

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertFalse(healthCheck.ignoreAllDegradedAlertTypes());

      assertNotNull(healthCheck.getIgnoredDegradedAlertTypes());
      assertTrue(healthCheck.getIgnoredDegradedAlertTypes().isEmpty());

      assertNotNull(healthCheck.getIgnoredUnavailableAlertTypes());
      assertFalse(healthCheck.getIgnoredUnavailableAlertTypes().isEmpty());
      assertEquals(healthCheck.getIgnoredUnavailableAlertTypes(),
           StaticUtils.setOf("test-unavailable-alert-type-1",
                "test-unavailable-alert-type-2"));

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception because of a non-ignored unavailable " +
             "alert type.");
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
   * Tests the behavior when the monitor entry does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMonitorEntryMissing()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(null, null);
         final LDAPConnection conn = ds.getConnection())
    {
      ds.delete("cn=monitor");

      final ActiveAlertsLDAPConnectionPoolHealthCheck healthCheck =
           new ActiveAlertsLDAPConnectionPoolHealthCheck(true, false, false,
                false, false, false, 0L, false, null, null);

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertFalse(healthCheck.ignoreAllDegradedAlertTypes());

      assertNotNull(healthCheck.getIgnoredDegradedAlertTypes());
      assertTrue(healthCheck.getIgnoredDegradedAlertTypes().isEmpty());

      assertNotNull(healthCheck.getIgnoredUnavailableAlertTypes());
      assertTrue(healthCheck.getIgnoredUnavailableAlertTypes().isEmpty());

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception because the monitor entry does not exist.");
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
   * Tests the behavior when an error occurs while attempting to retrieve the
   * monitor entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testErrorRetrievingMonitorEntry()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(null, null);
         final LDAPConnection conn = ds.getConnection())
    {
      conn.close(StaticUtils.NO_CONTROLS);

      final ActiveAlertsLDAPConnectionPoolHealthCheck healthCheck =
           new ActiveAlertsLDAPConnectionPoolHealthCheck(true, false, false,
                false, false, false, 0L, false, null, null);

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

      assertFalse(healthCheck.ignoreAllDegradedAlertTypes());

      assertNotNull(healthCheck.getIgnoredDegradedAlertTypes());
      assertTrue(healthCheck.getIgnoredDegradedAlertTypes().isEmpty());

      assertNotNull(healthCheck.getIgnoredUnavailableAlertTypes());
      assertTrue(healthCheck.getIgnoredUnavailableAlertTypes().isEmpty());

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception because the connection is closed, so an " +
             "error should have occurred while trying to retrieve the " +
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
   * Retrieves an in-memory directory server instance that contains a
   * "cn=monitor" entry with the provided set of degraded and/or unavailable
   * alert types.
   *
   * @param  degradedAlertTypes     The set of degraded alert types that
   *                                should be included in the "cn=monitor"
   *                                entry.  It may be {@code null} or empty if
   *                                no degraded alert types should be included.
   * @param  unavailableAlertTypes  The set of unavailable alert types that
   *                                should be included in the "cn=monitor"
   *                                entry.  It may be {@code null} or empty if
   *                                no unavailable alert types should be
   *                                included.
   *
   * @return  The in-memory directory server instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private InMemoryDirectoryServer getDS(final Set<String> degradedAlertTypes,
                                        final Set<String> unavailableAlertTypes)
          throws Exception
  {
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("cn=monitor");
    dsConfig.setSchema(null);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsConfig);

    final Entry monitorEntry = new Entry(
         "dn: cn=monitor",
         "objectClass: top",
         "objectClass: ds-general-monitor-entry",
         "cn: monitor");

    if ((degradedAlertTypes != null) && (! degradedAlertTypes.isEmpty()))
    {
      monitorEntry.addAttribute("degraded-alert-type", degradedAlertTypes);
    }

    if ((unavailableAlertTypes != null) && (! unavailableAlertTypes.isEmpty()))
    {
      monitorEntry.addAttribute("unavailable-alert-type",
           unavailableAlertTypes);
    }

    ds.add(monitorEntry);

    ds.startListening();
    return ds;
  }
}
