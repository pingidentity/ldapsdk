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



import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import com.unboundid.ldap.sdk.GetEntryLDAPConnectionPoolHealthCheck;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.json.JSONMessages.*;



/**
 * This class provides a data structure and set of logic for interacting with
 * the set of connection pool options in a JSON object provided to the
 * {@link LDAPConnectionDetailsJSONSpecification}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class ConnectionPoolOptions
{
  /**
   * The name of the field that may be used to indicate whether the connection
   * pool should be allowed to create connections if one is needed but none are
   * available.  If this field is present, then the value should be a boolean.
   * If it is not present, then a default of {@code true} will be assumed.
   */
  @NotNull private static final String FIELD_CREATE_IF_NECESSARY =
       "create-if-necessary";



  /**
   * The name of the field that may be used to specify the DN of an entry to
   * retrieve when performing periodic health checks.  If this field is present,
   * then the value should be a string containing the DN of an entry expected to
   * exist in the target directory server (and the entry string may be used to
   * indicate that the health check should retrieve the server root DSE).  If
   * this field is not present, then no attempt will be made to retrieve an
   * entry during health check processing.
   */
  @NotNull private static final String FIELD_HEALTH_CHECK_GET_ENTRY_DN =
       "health-check-get-entry-dn";



  /**
   * The name of the field that may be used to specify the maximum length of
   * time (in milliseconds) to wait when attempting to retrieve an entry during
   * health check processing.  If this field is present, then the value must be
   * a positive integer.  If it is absent, then a default of 10000 milliseconds
   * (ten seconds) will be used.
   */
  @NotNull private static final String
       FIELD_HEALTH_CHECK_GET_ENTRY_TIMEOUT_MILLIS =
            "health-check-get-entry-maximum-response-time-millis";



  /**
   * The name of the field that may be used to specify the length of time (in
   * milliseconds) between background health checks.  If this field is present,
   * then the value must be a positive integer.  If it is absent, then a default
   * of 60000 milliseconds (one minute) will be used.
   */
  @NotNull private static final String FIELD_HEALTH_CHECK_INTERVAL_MILLIS =
       "health-check-interval-millis";



  /**
   * The name of the field that may be used to specify the number of threads to
   * use when establishing the initial set of connections.  If this field is
   * present, then its value must be an integer greater than or equal to one,
   * and if the value is greater than one then the initial set of connections
   * will be established in parallel across that many threads.  If it is absent,
   * then a default of 1 will be assumed.
   */
  @NotNull private static final String FIELD_INITIAL_CONNECT_THREADS =
       "initial-connect-threads";



  /**
   * The name of the field that may be used to indicate whether connection pool
   * health checks should be invoked on newly-authenticated connections.  This
   * includes immediately after a newly-created connection has been
   * authenticated, as well as after any call to a connection pool's
   * {@code bindAndRevertAuthentication} or
   * {@code releaseAndReAuthenticateConnection} methods.  If this field is
   * present, then its value must be a boolean.  If it is absent, then a default
   * of {@code false} will be assumed.
   */
  @NotNull private static final String
       FIELD_INVOKE_AUTHENTICATION_HEALTH_CHECKS =
            "invoke-authentication-health-checks";



  /**
   * The name of the field that may be used to indicate whether connection pool
   * health checks should be periodically performed against available
   * connections in the background.  If this field is present, then its value
   * must be a boolean.  If it is absent, then a default of {@code true} will be
   * assumed.
   */
  @NotNull private static final String FIELD_INVOKE_BACKGROUND_HEALTH_CHECKS =
       "invoke-background-health-checks";



  /**
   * The name of the field that may be used to indicate whether connection pool
   * health checks should be invoked on connections that are checked out of the
   * pool.  If this field is present, then its value must be a boolean.  If it
   * is absent, then a default of {@code false} will be assumed.
   */
  @NotNull private static final String FIELD_INVOKE_CHECKOUT_HEALTH_CHECKS =
       "invoke-checkout-health-checks";



  /**
   * The name of the field that may be used to indicate whether connection pool
   * health checks should be invoked on newly-created connections.  If this
   * field is present, then its value must be a boolean.  If it is absent, then
   * a default of {@code false} will be assumed.
   */
  @NotNull private static final String FIELD_INVOKE_CREATE_HEALTH_CHECKS =
       "invoke-create-health-checks";



  /**
   * The name of the field that may be used to indicate whether connection pool
   * health checks should be invoked on connections after an operation has
   * failed in a manner that may indicate that the connection is no longer
   * valid.  If this field is present, then its value must be a boolean.  If it
   * is absent, then a default of {@code true} will be assumed.  Note that this
   * option only applies to failed attempts to process operations against the
   * connection pool directly (e.g., using the {@code LDAPConnectionPool.search}
   * method to perform a search), but not against failures encountered while a
   * connection is checked out of the pool.
   */
  @NotNull private static final String FIELD_INVOKE_EXCEPTION_HEALTH_CHECKS =
       "invoke-exception-health-checks";



  /**
   * The name of the field that may be used to indicate whether connection pool
   * health checks should be invoked on connections that are released back to
   * the pool.  If this field is present, then its value must be a boolean.  If
   * it is absent, then a default of {@code false} will be assumed.
   */
  @NotNull private static final String FIELD_INVOKE_RELEASE_HEALTH_CHECKS =
       "invoke-release-health-checks";



  /**
   * The name of the field that may be used to specify the maximum length of
   * time (in milliseconds) that a connection should be established before a new
   * connection is created to take its place.  Setting a maximum connection age
   * can be useful in environments in which idle connections may be closed after
   * a period of time, or to help ensure that connections are eventually
   * rebalanced in a desired manner after a failure causes connections to be
   * failed over.  If this field is present, then its value must be an integer
   * value that is greater than or equal to zero.  If it is absent, then a
   * default of 0 will be assumed, which indicates that connections should not
   * be automatically closed after a specified period of time.
   */
  @NotNull private static final String FIELD_MAX_CONNECTION_AGE_MILLIS =
       "maximum-connection-age-millis";



  /**
   * The name of the field that may be used to specify the maximum length of
   * time that a connection created as a replacement for a defunct connection
   * should be established.  If specified, then its value must be an integer
   * value that is greater than or equal to zero (with zero indicating that
   * these connections should not be automatically closed after a specified
   * period of time).  If it is absent, then the maximum connection age will be
   * used for these connections.
   */
  @NotNull private static final String
       FIELD_MAX_DEFUNCT_REPLACEMENT_CONNECTION_AGE_MILLIS =
            "maximum-defunct-replacement-connection-age-millis";



  /**
   * The name of the field that may be used to specify the maximum length of
   * time (in milliseconds) that the connection pool should wait for a
   * connection to be released if a connection is needed but none are available.
   * If this field is present, then its value must be an integer value that is
   * greater than or equal to zero.  If it is absent, then a default of 0 will
   * be assumed, which indicates that the pool should not wait for a connection
   * if none are immediately available, but should either create a new
   * connection or throw an exception (based on the value of the
   * create-if-necessary field).
   */
  @NotNull private static final String FIELD_MAX_WAIT_TIME_MILLIS =
       "maximum-wait-time-millis";



  /**
   * The name of the field that may be used to indicate whether to retry
   * operations on a newly-created connection if the initial attempt fails in a
   * manner that indicates the connection may no longer be valid.  Note that
   * this option only applies to failed attempts to process operations against
   * the connection pool directly (e.g., using the
   * {@code LDAPConnectionPool.search} method to perform a search), but not
   * against failures encountered while a connection is checked out of the pool.
   * If present, then the value of this field may be either a simple boolean to
   * indicate whether to retry operations of any type, or it may be an array of
   * strings (in which valid values are "add", "bind", "compare", "delete",
   * "extended", "modify", "modify-dn", and "search") to indicate the specific
   * types of operations for which automatic retry should be enabled.  If it is
   * absent, then no automatic retry will be attempted.
   */
  @NotNull private static final String FIELD_RETRY_FAILED_OPS =
       "retry-failed-operations-due-to-invalid-connections";



  // Indicates whether to create new connections if necessary.
  private final boolean createIfNecessary;

  // The health check to use for connection pools.
  @Nullable private final GetEntryLDAPConnectionPoolHealthCheck healthCheck;

  // The number of concurrent threads to create the initial set of connections.
  private final int initialConnectThreads;

  // The health check interval.
  private final long healthCheckIntervalMillis;

  // The maximum connection age.
  private final long maxConnectionAgeMillis;

  // The maximum wait time.
  private final long maxWaitTimeMillis;

  // The maximum defunct replacement connection age.
  @Nullable private final Long maxDefunctReplacementConnectionAgeMillis;

  // The set of operation types for which to enable retry.
  @NotNull private final Set<OperationType> retryOperationTypes;



  /**
   * Creates a new set of connection pool options from the information contained
   * in the provided JSON object.
   *
   * @param  connectionDetailsObject  The JSON object containing the LDAP
   *                                  connection details specification.
   *
   * @throws  LDAPException  If there is a problem with the connection pool
   *                         options data in the provided JSON object.
   */
  ConnectionPoolOptions(@NotNull final JSONObject connectionDetailsObject)
       throws LDAPException
  {
    boolean create                   = true;
    boolean invokeAuthentication     = false;
    boolean invokeBackground         = true;
    boolean invokeCheckout           = false;
    boolean invokeCreate             = false;
    boolean invokeException          = true;
    boolean invokeRelease            = false;
    int     initialThreads           = 1;
    long    getEntryTimeout          = 10_000L;
    long    healthCheckInterval      = 60_000L;
    long    maxConnectionAge         = 0L;
    long    maxWaitTime              = 0L;
    Long    maxDefunctReplacementAge = null;
    String  getDN                    = null;

    final Set<OperationType> retryTypes = EnumSet.noneOf(OperationType.class);

    final JSONObject o = LDAPConnectionDetailsJSONSpecification.getObject(
         connectionDetailsObject,
         LDAPConnectionDetailsJSONSpecification.FIELD_CONNECTION_POOL_OPTIONS);
    if (o != null)
    {
      LDAPConnectionDetailsJSONSpecification.validateAllowedFields(o,
           LDAPConnectionDetailsJSONSpecification.FIELD_CONNECTION_POOL_OPTIONS,
           FIELD_CREATE_IF_NECESSARY,
           FIELD_HEALTH_CHECK_GET_ENTRY_DN,
           FIELD_HEALTH_CHECK_GET_ENTRY_TIMEOUT_MILLIS,
           FIELD_HEALTH_CHECK_INTERVAL_MILLIS,
           FIELD_INITIAL_CONNECT_THREADS,
           FIELD_INVOKE_AUTHENTICATION_HEALTH_CHECKS,
           FIELD_INVOKE_BACKGROUND_HEALTH_CHECKS,
           FIELD_INVOKE_CHECKOUT_HEALTH_CHECKS,
           FIELD_INVOKE_CREATE_HEALTH_CHECKS,
           FIELD_INVOKE_EXCEPTION_HEALTH_CHECKS,
           FIELD_INVOKE_RELEASE_HEALTH_CHECKS,
           FIELD_MAX_CONNECTION_AGE_MILLIS,
           FIELD_MAX_DEFUNCT_REPLACEMENT_CONNECTION_AGE_MILLIS,
           FIELD_MAX_WAIT_TIME_MILLIS,
           FIELD_RETRY_FAILED_OPS);

      create = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_CREATE_IF_NECESSARY, create);

      invokeAuthentication = LDAPConnectionDetailsJSONSpecification.getBoolean(
           o, FIELD_INVOKE_AUTHENTICATION_HEALTH_CHECKS, invokeAuthentication);

      invokeBackground = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_INVOKE_BACKGROUND_HEALTH_CHECKS, invokeBackground);

      invokeCheckout = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_INVOKE_CHECKOUT_HEALTH_CHECKS, invokeCheckout);

      invokeCreate = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_INVOKE_CREATE_HEALTH_CHECKS, invokeCreate);

      invokeException = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_INVOKE_EXCEPTION_HEALTH_CHECKS, invokeException);

      invokeRelease = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_INVOKE_RELEASE_HEALTH_CHECKS, invokeRelease);

      initialThreads = LDAPConnectionDetailsJSONSpecification.getInt(o,
           FIELD_INITIAL_CONNECT_THREADS, initialThreads, 1, null);

      getEntryTimeout = LDAPConnectionDetailsJSONSpecification.getLong(o,
           FIELD_HEALTH_CHECK_GET_ENTRY_TIMEOUT_MILLIS, getEntryTimeout, 1L,
           null);

      healthCheckInterval = LDAPConnectionDetailsJSONSpecification.getLong(o,
           FIELD_HEALTH_CHECK_INTERVAL_MILLIS, healthCheckInterval, 1L, null);

      maxConnectionAge = LDAPConnectionDetailsJSONSpecification.getLong(o,
           FIELD_MAX_CONNECTION_AGE_MILLIS, maxConnectionAge, 0L, null);

      maxWaitTime = LDAPConnectionDetailsJSONSpecification.getLong(o,
           FIELD_MAX_WAIT_TIME_MILLIS, maxWaitTime, 0L, null);

      maxDefunctReplacementAge = LDAPConnectionDetailsJSONSpecification.getLong(
           o, FIELD_MAX_DEFUNCT_REPLACEMENT_CONNECTION_AGE_MILLIS,
           maxDefunctReplacementAge, 0L, null);

      getDN = LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_HEALTH_CHECK_GET_ENTRY_DN, getDN);

      final JSONValue retryTypesValue = o.getField(FIELD_RETRY_FAILED_OPS);
      if (retryTypesValue != null)
      {
        if (retryTypesValue instanceof JSONBoolean)
        {
          if (((JSONBoolean) retryTypesValue).booleanValue())
          {
            retryTypes.addAll(EnumSet.allOf(OperationType.class));
          }
        }
        else if (retryTypesValue instanceof JSONArray)
        {
          for (final JSONValue v : ((JSONArray) retryTypesValue).getValues())
          {
            if (v instanceof JSONString)
            {
              final String s =
                   StaticUtils.toLowerCase(((JSONString) v).stringValue());
              if (s.equals("add"))
              {
                retryTypes.add(OperationType.ADD);
              }
              else if (s.equals("bind"))
              {
                retryTypes.add(OperationType.BIND);
              }
              else if (s.equals("compare"))
              {
                retryTypes.add(OperationType.COMPARE);
              }
              else if (s.equals("delete"))
              {
                retryTypes.add(OperationType.DELETE);
              }
              else if (s.equals("extended"))
              {
                retryTypes.add(OperationType.EXTENDED);
              }
              else if (s.equals("modify"))
              {
                retryTypes.add(OperationType.MODIFY);
              }
              else if (s.equals("modify-dn"))
              {
                retryTypes.add(OperationType.MODIFY_DN);
              }
              else if (s.equals("search"))
              {
                retryTypes.add(OperationType.SEARCH);
              }
              else
              {
                throw new LDAPException(ResultCode.PARAM_ERROR,
                     ERR_POOL_OPTIONS_INVALID_RETRY_TYPES.get(
                          FIELD_RETRY_FAILED_OPS));
              }
            }
            else
            {
              throw new LDAPException(ResultCode.PARAM_ERROR,
                   ERR_POOL_OPTIONS_INVALID_RETRY_TYPES.get(
                        FIELD_RETRY_FAILED_OPS));
            }
          }
        }
        else
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_POOL_OPTIONS_INVALID_RETRY_TYPES.get(
                    FIELD_RETRY_FAILED_OPS));
        }
      }
    }

    createIfNecessary                        = create;
    initialConnectThreads                    = initialThreads;
    healthCheckIntervalMillis                = healthCheckInterval;
    maxConnectionAgeMillis                   = maxConnectionAge;
    maxDefunctReplacementConnectionAgeMillis = maxDefunctReplacementAge;
    maxWaitTimeMillis                        = maxWaitTime;

    retryOperationTypes = Collections.unmodifiableSet(retryTypes);

    if (getDN == null)
    {
      healthCheck = null;
    }
    else
    {
      healthCheck = new GetEntryLDAPConnectionPoolHealthCheck(getDN,
           getEntryTimeout, invokeCreate, invokeAuthentication, invokeCheckout,
           invokeRelease, invokeBackground, invokeException);
    }
  }



  /**
   * Retrieves the number of initial connect threads.
   *
   * @return  The number of initial connect threads.
   */
  int getInitialConnectThreads()
  {
    return initialConnectThreads;
  }



  /**
   * Retrieves the health check that should be used for connection pools.
   *
   * @return  The health check that should be used for connection pools.
   */
  @Nullable()
  GetEntryLDAPConnectionPoolHealthCheck getHealthCheck()
  {
    return healthCheck;
  }



  /**
   * Updates the provided connection pool to apply these settings.
   *
   * @param  pool  The connection pool to update.
   */
  void applyConnectionPoolSettings(@NotNull final LDAPConnectionPool pool)
  {
    pool.setCreateIfNecessary(createIfNecessary);
    pool.setHealthCheckIntervalMillis(healthCheckIntervalMillis);
    pool.setMaxConnectionAgeMillis(maxConnectionAgeMillis);
    pool.setMaxDefunctReplacementConnectionAgeMillis(
         maxDefunctReplacementConnectionAgeMillis);
    pool.setMaxWaitTimeMillis(maxWaitTimeMillis);
    pool.setRetryFailedOperationsDueToInvalidConnections(retryOperationTypes);
  }
}
