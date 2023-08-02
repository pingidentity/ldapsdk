/*
 * Copyright 2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023 Ping Identity Corporation
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
 * Copyright (C) 2023 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a set of test cases for the
 * {@link PooledReferralConnectorProperties} class.
 */
public final class PooledReferralConnectorPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the default values for all of the properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code initialConnectionsPerPool} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitialConnectionsPerPool()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setInitialConnectionsPerPool(2);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 2);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code maximumConnectionsPerPool} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaximumConnectionsPerPool()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setMaximumConnectionsPerPool(123);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 123);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the
   * {@code retryFailedOperationsDueToInvalidConnections} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRetryFailedOperationsDueToInvalidConnections()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setRetryFailedOperationsDueToInvalidConnections(false);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertFalse(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code maximumConnectionAgeMillis} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaximumConnectionAgeMillis()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setMaximumConnectionAgeMillis(1234L);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1234L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setMaximumConnectionAgeMillis(-1L);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code maximumPoolAgeMillis} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaximumPoolAgeMillis()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setMaximumPoolAgeMillis(12345678L);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 12345678L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setMaximumPoolAgeMillis(-1L);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code maximumPoolIdleDurationMillis} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaximumPoolIdleDurationMillis()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setMaximumPoolIdleDurationMillis(12345L);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 12345L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setMaximumPoolIdleDurationMillis(-1L);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 0L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code healthCheck} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHealthCheck()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setHealthCheck(new GetEntryLDAPConnectionPoolHealthCheck("",
         1234L, false, false, false, true, true));
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNotNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code healthCheckIntervalMillis} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHealthCheckIntervalMillis()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setHealthCheckIntervalMillis(12345L);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 12345L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code bindRequest} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequest()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    final SimpleBindRequest bindRequest = new SimpleBindRequest(
         "uid=test.user,ou=People,dc=example,dc=com", "password");
    properties.setBindRequest(bindRequest);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNotNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setBindRequest(null);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code connectionOptions} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectionOptiosn()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setConnectionOptions(new LDAPConnectionOptions());
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNotNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setConnectionOptions(null);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code ldapURLSecurityType} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPURLSecurityType()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    for (final PooledReferralConnectorLDAPURLSecurityType securityType :
         PooledReferralConnectorLDAPURLSecurityType.values())
    {
      properties.setLDAPURLSecurityType(securityType);
      properties = new PooledReferralConnectorProperties(properties);

      assertEquals(properties.getInitialConnectionsPerPool(), 1);
      assertEquals(properties.getMaximumConnectionsPerPool(), 10);
      assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
      assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
      assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
      assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
      assertNull(properties.getHealthCheck());
      assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
      assertNull(properties.getBindRequest());
      assertNull(properties.getConnectionOptions());
      assertEquals(properties.getLDAPURLSecurityType(), securityType);
      assertNull(properties.getSSLSocketFactory());
      assertEquals(properties.getBackgroundThreadCheckIntervalMillis(),
           10_000L);

      assertNotNull(properties.toString());
    }
  }



  /**
   * Tests the behavior for the {@code sslSocketFactory} property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSLSocketFacotry()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    properties.setSSLSocketFactory(sslUtil.createSSLSocketFactory());
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNotNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setSSLSocketFactory(null);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the {@code backgroundThreadCheckIntervalMillis}
   * property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBackgroundThreadCheckIntervalMillis()
         throws Exception
  {
    PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();

    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 10_000L);

    assertNotNull(properties.toString());

    properties.setBackgroundThreadCheckIntervalMillis(12345L);
    properties = new PooledReferralConnectorProperties(properties);

    assertEquals(properties.getInitialConnectionsPerPool(), 1);
    assertEquals(properties.getMaximumConnectionsPerPool(), 10);
    assertTrue(properties.retryFailedOperationsDueToInvalidConnections());
    assertEquals(properties.getMaximumConnectionAgeMillis(), 1_800_000L);
    assertEquals(properties.getMaximumPoolAgeMillis(), 0L);
    assertEquals(properties.getMaximumPoolIdleDurationMillis(), 3_600_000L);
    assertNull(properties.getHealthCheck());
    assertEquals(properties.getHealthCheckIntervalMillis(), 60_000L);
    assertNull(properties.getBindRequest());
    assertNull(properties.getConnectionOptions());
    assertEquals(properties.getLDAPURLSecurityType(),
         PooledReferralConnectorLDAPURLSecurityType.
              CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS);
    assertNull(properties.getSSLSocketFactory());
    assertEquals(properties.getBackgroundThreadCheckIntervalMillis(), 12345L);

    assertNotNull(properties.toString());
  }
}
