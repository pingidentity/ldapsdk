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
 * This class provides a set of unit tests for the lockdown mode LDAP connection
 * pool health check.
 */
public final class LockdownModeLDAPConnectionPoolHealthCheckTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when the monitor entry exists and can be used to verify
   * that the server is not currently in lockdown mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotInLockdownMode()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(false);
         final LDAPConnection conn = ds.getConnection())
    {
      final LockdownModeLDAPConnectionPoolHealthCheck healthCheck =
           new LockdownModeLDAPConnectionPoolHealthCheck(true, true, true, true,
                true, true, 0L);

      assertTrue(healthCheck.invokeOnCreate());
      assertTrue(healthCheck.invokeAfterAuthentication());
      assertTrue(healthCheck.invokeOnCheckout());
      assertTrue(healthCheck.invokeOnRelease());
      assertTrue(healthCheck.invokeForBackgroundChecks());
      assertTrue(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 5_000L);

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
   * Tests the behavior when the monitor entry exists and can be used to verify
   * that the server is currently in lockdown mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInLockdownMode()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(true);
         final LDAPConnection conn = ds.getConnection())
    {
      final LockdownModeLDAPConnectionPoolHealthCheck healthCheck =
           new LockdownModeLDAPConnectionPoolHealthCheck(true, false, false,
                false, false, false, 1_234L);

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 1_234L);

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception when validating a newly created " +
             "connection when the server is expected to be in lockdown mode.");
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
   * Tests the behavior when the monitor entry exists but does not include the
   * attribute used to determine whether the server is in lockdown mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingLockdownModeAttribute()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(null);
         final LDAPConnection conn = ds.getConnection())
    {
      final LockdownModeLDAPConnectionPoolHealthCheck healthCheck =
           new LockdownModeLDAPConnectionPoolHealthCheck(true, false, false,
                false, false, false, 1_234L);

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 1_234L);

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception when validating a newly created " +
             "connection when the monitor entry is missing the " +
             "is-in-lockdown-mode attribute.");
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
  public void testMissingMonitorEntry()
         throws Exception
  {
    try (final InMemoryDirectoryServer ds = getDS(false);
         final LDAPConnection conn = ds.getConnection())
    {
      conn.delete("cn=Status Health Summary,cn=monitor");

      final LockdownModeLDAPConnectionPoolHealthCheck healthCheck =
           new LockdownModeLDAPConnectionPoolHealthCheck(true, false, false,
                false, false, false, 1_234L);

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 1_234L);

      assertNotNull(healthCheck.toString());

      try
      {
        healthCheck.ensureNewConnectionValid(conn);
        fail("Expected an exception when validating a newly created " +
             "connection when the monitor entry is missing.");
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
    try (final InMemoryDirectoryServer ds = getDS(false);
         final LDAPConnection conn = ds.getConnection())
    {
      conn.close(StaticUtils.NO_CONTROLS);

      final LockdownModeLDAPConnectionPoolHealthCheck healthCheck =
           new LockdownModeLDAPConnectionPoolHealthCheck(true, false, false,
                false, false, false, 1_234L);

      assertTrue(healthCheck.invokeOnCreate());
      assertFalse(healthCheck.invokeAfterAuthentication());
      assertFalse(healthCheck.invokeOnCheckout());
      assertFalse(healthCheck.invokeOnRelease());
      assertFalse(healthCheck.invokeForBackgroundChecks());
      assertFalse(healthCheck.invokeOnException());

      assertEquals(healthCheck.getMaxResponseTimeMillis(), 1_234L);

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
   * Retrieves an in-memory directory server instance that contains a
   * "cn=Status Health Summary,cn=monitor" entry with the specified Boolean
   * value for the is-in-lockdown-mode attribute.
   *
   * @param  isInLockdownMode  The value that should be used for the
   *                           is-in-lockdown-mode attribute in the monitor
   *                           entry.  It may be {@code null} if the attribute
   *                           should not be included in the entry.
   *
   * @return  The in-memory directory server instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private InMemoryDirectoryServer getDS(final Boolean isInLockdownMode)
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

    final Entry statusHealthSummaryMonitorEntry = new Entry(
         "dn: cn=Status Health Summary,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-status-health-summary-monitor",
         "cn: Status Health Summary");

    if (isInLockdownMode != null)
    {
      statusHealthSummaryMonitorEntry.addAttribute(
           "is-in-lockdown-mode", String.valueOf(isInLockdownMode));
    }

    ds.add(statusHealthSummaryMonitorEntry);

    ds.startListening();
    return ds;
  }
}
