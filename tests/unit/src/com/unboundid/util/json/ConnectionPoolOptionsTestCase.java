/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import java.util.EnumSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.GetEntryLDAPConnectionPoolHealthCheck;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPConnectionPoolHealthCheck;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;



/**
 * This class provides a set of test cases for the connection pool options
 * class.
 */
public final class ConnectionPoolOptionsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for the case in which the JSON object does not have the
   * connection-pool-options field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoOptions()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    final LDAPConnectionPool pool = spec.createConnectionPool(1, 10);

    assertTrue(pool.getCreateIfNecessary());

    assertNotNull(pool.getHealthCheck());
    assertEquals(pool.getHealthCheck().getClass(),
         LDAPConnectionPoolHealthCheck.class);

    assertEquals(pool.getMaxConnectionAgeMillis(), 0L);

    assertNull(pool.getMaxDefunctReplacementConnectionAgeMillis());

    assertEquals(pool.getMaxWaitTimeMillis(), 0L);

    assertNotNull(pool.getOperationTypesToRetryDueToInvalidConnections());
    assertTrue(pool.getOperationTypesToRetryDueToInvalidConnections().
         isEmpty());

    pool.close();
  }



  /**
   * Tests the behavior for the case in which the JSON object has a
   * connection-pool-options field whose value is an empty object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyOptions()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("connection-pool-options", new JSONObject()));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    final LDAPConnectionPool pool = spec.createConnectionPool(1, 10);

    assertTrue(pool.getCreateIfNecessary());

    assertNotNull(pool.getHealthCheck());
    assertEquals(pool.getHealthCheck().getClass(),
         LDAPConnectionPoolHealthCheck.class);

    assertEquals(pool.getMaxConnectionAgeMillis(), 0L);

    assertNull(pool.getMaxDefunctReplacementConnectionAgeMillis());

    assertEquals(pool.getMaxWaitTimeMillis(), 0L);

    assertNotNull(pool.getOperationTypesToRetryDueToInvalidConnections());
    assertTrue(pool.getOperationTypesToRetryDueToInvalidConnections().
         isEmpty());

    pool.close();
  }



  /**
   * Tests the behavior for the case in which the JSON object has a
   * connection-pool-options field with a complete set of options set to
   * non-default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteOptions()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("connection-pool-options", new JSONObject(
              new JSONField("create-if-necessary", false),
              new JSONField("health-check-get-entry-dn", ""),
              new JSONField(
                   "health-check-get-entry-maximum-response-time-millis",
                   1234L),
              new JSONField("health-check-interval-millis", 10000L),
              new JSONField("initial-connect-threads", 2),
              new JSONField("invoke-background-health-checks", false),
              new JSONField("invoke-checkout-health-checks", true),
              new JSONField("invoke-create-health-checks", true),
              new JSONField("invoke-authentication-health-checks", true),
              new JSONField("invoke-exception-health-checks", false),
              new JSONField("invoke-release-health-checks", true),
              new JSONField("maximum-connection-age-millis", 300000L),
              new JSONField("maximum-defunct-replacement-connection-age-millis",
                   100000L),
              new JSONField("maximum-wait-time-millis", 5000L),
              new JSONField(
                   "retry-failed-operations-due-to-invalid-connections",
                   true))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    final LDAPConnectionPool pool = spec.createConnectionPool(1, 10);

    assertFalse(pool.getCreateIfNecessary());

    assertNotNull(pool.getHealthCheck());
    assertEquals(pool.getHealthCheck().getClass(),
         GetEntryLDAPConnectionPoolHealthCheck.class);

    final GetEntryLDAPConnectionPoolHealthCheck healthCheck =
         (GetEntryLDAPConnectionPoolHealthCheck) pool.getHealthCheck();
    assertDNsEqual(healthCheck.getEntryDN(), "");
    assertEquals(healthCheck.getMaxResponseTimeMillis(), 1234L);
    assertFalse(healthCheck.invokeForBackgroundChecks());
    assertTrue(healthCheck.invokeOnCheckout());
    assertTrue(healthCheck.invokeOnCreate());
    assertFalse(healthCheck.invokeOnException());
    assertTrue(healthCheck.invokeOnRelease());

    assertEquals(pool.getMaxConnectionAgeMillis(), 300000L);

    assertNotNull(pool.getMaxDefunctReplacementConnectionAgeMillis());
    assertEquals(pool.getMaxDefunctReplacementConnectionAgeMillis().longValue(),
         100000L);

    assertEquals(pool.getMaxWaitTimeMillis(), 5000L);

    assertNotNull(pool.getOperationTypesToRetryDueToInvalidConnections());
    assertFalse(pool.getOperationTypesToRetryDueToInvalidConnections().
         isEmpty());

    pool.close();
  }



  /**
   * Tests the behavior for the case in which the connection pool options
   * specifies the set of retry operation types to include all valid options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRetryTypesValid()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("connection-pool-options", new JSONObject(
              new JSONField(
                   "retry-failed-operations-due-to-invalid-connections",
                   new JSONArray(
                        new JSONString("add"),
                        new JSONString("bind"),
                        new JSONString("compare"),
                        new JSONString("delete"),
                        new JSONString("extended"),
                        new JSONString("modify"),
                        new JSONString("modify-dn"),
                        new JSONString("search"))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    final LDAPConnectionPool pool = spec.createConnectionPool(1, 10);

    assertNotNull(pool.getOperationTypesToRetryDueToInvalidConnections());
    assertFalse(pool.getOperationTypesToRetryDueToInvalidConnections().
         isEmpty());
    assertEquals(pool.getOperationTypesToRetryDueToInvalidConnections(),
         EnumSet.of(OperationType.ADD, OperationType.BIND,
              OperationType.COMPARE, OperationType.DELETE,
              OperationType.EXTENDED, OperationType.MODIFY,
              OperationType.MODIFY_DN, OperationType.SEARCH));

    pool.close();
  }



  /**
   * Tests the behavior for the case in which the connection pool options
   * specifies the set of retry operation types but includes an invalid string
   * in the set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testRetryTypesInvalidString()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("connection-pool-options", new JSONObject(
              new JSONField(
                   "retry-failed-operations-due-to-invalid-connections",
                   new JSONArray(
                        new JSONString("add"),
                        new JSONString("bind"),
                        new JSONString("compare"),
                        new JSONString("delete"),
                        new JSONString("extended"),
                        new JSONString("modify"),
                        new JSONString("modify-dn"),
                        new JSONString("invalid"))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the connection pool options
   * in which the value for the
   * retry-failed-operations-due-to-invalid-connections field is neither a
   * boolean nor an array of strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testRetryTypesInvalidValueType()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("connection-pool-options", new JSONObject(
              new JSONField(
                   "retry-failed-operations-due-to-invalid-connections",
                   1234))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the connection pool options
   * specifies the set of retry operation types but includes an invalid string
   * in the set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testRetryTypesInvalidArrayElementType()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("connection-pool-options", new JSONObject(
              new JSONField(
                   "retry-failed-operations-due-to-invalid-connections",
                   new JSONArray(
                        new JSONString("add"),
                        new JSONString("bind"),
                        new JSONString("compare"),
                        new JSONString("delete"),
                        new JSONString("extended"),
                        new JSONString("modify"),
                        new JSONString("modify-dn"),
                        JSONBoolean.TRUE)))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }
}
