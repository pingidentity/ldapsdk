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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides general information about
 * an LDAP external server used by the Directory Proxy Server.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * Information that it may make available includes:
 * <UL>
 *   <LI>The address, port, and security mechanism used to communicate with the
 *       server.</LI>
 *   <LI>The DN of the configuration entry for the load-balancing algorithm that
 *       is using the LDAP external server object.</LI>
 *   <LI>Information about the health of the LDAP external server.</LI>
 *   <LI>The number of attempted, successful, and failed operations processed
 *       using the LDAP external server.</LI>
 * </UL>
 * The server should present an LDAP external server monitor entry for each
 * server used by each load-balancing algorithm.  These entries can be retrieved
 * using the {@link MonitorManager#getLDAPExternalServerMonitorEntries} method.
 * These entries provide specific methods for accessing this information.
 * Alternately, the information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPExternalServerMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in LDAP external server monitor entries.
   */
  @NotNull protected static final String LDAP_EXTERNAL_SERVER_MONITOR_OC =
       "ds-ldap-external-server-monitor-entry";



  /**
   * The name of the attribute used to provide the number of add operations
   * attempted in the backend server.
   */
  @NotNull private static final String ATTR_ADD_ATTEMPTS = "add-attempts";



  /**
   * The name of the attribute used to provide the number of add operations
   * that failed.
   */
  @NotNull private static final String ATTR_ADD_FAILURES = "add-failures";



  /**
   * The name of the attribute used to provide the number of add operations
   * completed successfully.
   */
  @NotNull private static final String ATTR_ADD_SUCCESSES = "add-successes";



  /**
   * The name of the attribute used to provide the number of bind operations
   * attempted in the backend server.
   */
  @NotNull private static final String ATTR_BIND_ATTEMPTS = "bind-attempts";



  /**
   * The name of the attribute used to provide the number of bind operations
   * that failed.
   */
  @NotNull private static final String ATTR_BIND_FAILURES = "bind-failures";



  /**
   * The name of the attribute used to provide the number of bind operations
   * completed successfully.
   */
  @NotNull private static final String ATTR_BIND_SUCCESSES = "bind-successes";



  /**
   * The name of the attribute used to provide the communication security
   * mechanism.
   */
  @NotNull private static final String ATTR_COMMUNICATION_SECURITY =
       "communication-security";



  /**
   * The name of the attribute used to provide the number of compare operations
   * attempted in the backend server.
   */
  @NotNull private static final String ATTR_COMPARE_ATTEMPTS =
       "compare-attempts";



  /**
   * The name of the attribute used to provide the number of compare operations
   * that failed.
   */
  @NotNull private static final String ATTR_COMPARE_FAILURES =
       "compare-failures";



  /**
   * The name of the attribute used to provide the number of compare operations
   * completed successfully.
   */
  @NotNull private static final String ATTR_COMPARE_SUCCESSES =
       "compare-successes";



  /**
   * The name of the attribute used to provide the number of delete operations
   * attempted in the backend server.
   */
  @NotNull private static final String ATTR_DELETE_ATTEMPTS = "delete-attempts";



  /**
   * The name of the attribute used to provide the number of delete operations
   * that failed.
   */
  @NotNull private static final String ATTR_DELETE_FAILURES = "delete-failures";



  /**
   * The name of the attribute used to provide the number of delete operations
   * completed successfully.
   */
  @NotNull private static final String ATTR_DELETE_SUCCESSES =
       "delete-successes";



  /**
   * The name of the attribute used to provide health check messages.
   */
  @NotNull private static final String ATTR_HEALTH_CHECK_MESSAGE =
       "health-check-message";



  /**
   * The name of the attribute used to provide the health check state.
   */
  @NotNull private static final String ATTR_HEALTH_CHECK_STATE =
       "health-check-state";



  /**
   * The name of the attribute used to provide the health check score.
   */
  @NotNull private static final String ATTR_HEALTH_CHECK_SCORE =
       "health-check-score";



  /**
   * The name of the attribute used to provide the time the health check
   * information was last updated.
   */
  @NotNull private static final String ATTR_HEALTH_CHECK_UPDATE_TIME =
       "health-check-update-time";



  /**
   * The name of the attribute used to provide the DN of the load-balancing
   * algorithm configuration entry.
   */
  @NotNull private static final String ATTR_LOAD_BALANCING_ALGORITHM_DN =
       "load-balancing-algorithm";



  /**
   * The name of the attribute used to provide the number of modify operations
   * attempted in the backend server.
   */
  @NotNull private static final String ATTR_MODIFY_ATTEMPTS = "modify-attempts";



  /**
   * The name of the attribute used to provide the number of modify operations
   * that failed.
   */
  @NotNull private static final String ATTR_MODIFY_FAILURES = "modify-failures";



  /**
   * The name of the attribute used to provide the number of modify operations
   * completed successfully.
   */
  @NotNull private static final String ATTR_MODIFY_SUCCESSES =
       "modify-successes";



  /**
   * The name of the attribute used to provide the number of modify DN
   * operations attempted in the backend server.
   */
  @NotNull private static final String ATTR_MODIFY_DN_ATTEMPTS =
       "modify-dn-attempts";



  /**
   * The name of the attribute used to provide the number of modify DN
   * operations that failed.
   */
  @NotNull private static final String ATTR_MODIFY_DN_FAILURES =
       "modify-dn-failures";



  /**
   * The name of the attribute used to provide the number of modify DN
   * operations completed successfully.
   */
  @NotNull private static final String ATTR_MODIFY_DN_SUCCESSES =
       "modify-dn-successes";



  /**
   * The name of the attribute used to provide the number of search operations
   * attempted in the backend server.
   */
  @NotNull private static final String ATTR_SEARCH_ATTEMPTS = "search-attempts";



  /**
   * The name of the attribute used to provide the number of search operations
   * that failed.
   */
  @NotNull private static final String ATTR_SEARCH_FAILURES = "search-failures";



  /**
   * The name of the attribute used to provide the number of search operations
   * completed successfully.
   */
  @NotNull private static final String ATTR_SEARCH_SUCCESSES =
       "search-successes";



  /**
   * The name of the attribute used to provide the server address.
   */
  @NotNull private static final String ATTR_SERVER_ADDRESS = "server-address";



  /**
   * The name of the attribute used to provide the server port.
   */
  @NotNull private static final String ATTR_SERVER_PORT = "server-port";



  /**
   * The prefix for attributes providing information from a connection pool used
   * only for bind operations.
   */
  @NotNull private static final String ATTR_PREFIX_BIND_POOL = "bind-";



  /**
   * The prefix for attributes providing information from a connection pool used
   * for all types of operations.
   */
  @NotNull private static final String ATTR_PREFIX_COMMON_POOL = "common-";



  /**
   * The prefix for attributes providing information from a connection pool used
   * only for non-bind operations.
   */
  @NotNull private static final String ATTR_PREFIX_NONBIND_POOL = "non-bind-";



  /**
   * The suffix for the attribute used to provide the number of available
   * connections from a pool.
   */
  @NotNull private static final String ATTR_SUFFIX_AVAILABLE_CONNS =
       "pool-available-connections";



  /**
   * The suffix for the attribute used to provide the number of connections
   * closed as defunct.
   */
  @NotNull private static final String ATTR_SUFFIX_CLOSED_DEFUNCT =
       "pool-num-closed-defunct";



  /**
   * The suffix for the attribute used to provide the number of connections
   * closed as expired.
   */
  @NotNull private static final String ATTR_SUFFIX_CLOSED_EXPIRED =
       "pool-num-closed-expired";



  /**
   * The suffix for the attribute used to provide the number of connections
   * closed as unneeded.
   */
  @NotNull private static final String ATTR_SUFFIX_CLOSED_UNNEEDED =
       "pool-num-closed-unneeded";



  /**
   * The suffix for the attribute used to provide the number of failed
   * checkouts.
   */
  @NotNull private static final String ATTR_SUFFIX_FAILED_CHECKOUTS =
       "pool-num-failed-checkouts";



  /**
   * The suffix for the attribute used to provide the number of failed
   * connection attempts.
   */
  @NotNull private static final String ATTR_SUFFIX_FAILED_CONNECTS =
       "pool-num-failed-connection-attempts";



  /**
   * The suffix for the attribute used to provide the maximum number of
   * available connections from a pool.
   */
  @NotNull private static final String ATTR_SUFFIX_MAX_AVAILABLE_CONNS =
       "pool-max-available-connections";



  /**
   * The suffix for the attribute used to provide the number of connections
   * released as valid back to the pool.
   */
  @NotNull private static final String ATTR_SUFFIX_RELEASED_VALID =
       "pool-num-released-valid";



  /**
   * The suffix for the attribute used to provide the number of successful
   * checkouts.
   */
  @NotNull private static final String ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS =
       "pool-num-successful-checkouts";



  /**
   * The suffix for the attribute used to provide the number of successful
   * checkouts after waiting for a connection to become available.
   */
  @NotNull private static final String
       ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_AFTER_WAITING =
            "pool-num-successful-checkouts-after-waiting";



  /**
   * The suffix for the attribute used to provide the number of successful
   * checkouts after creating a new connection.
   */
  @NotNull private static final String
       ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_NEW_CONN =
            "pool-num-successful-checkouts-new-connection";



  /**
   * The suffix for the attribute used to provide the number of successful
   * checkouts without waiting.
   */
  @NotNull private static final String
       ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_WITHOUT_WAITING =
            "pool-num-successful-checkouts-without-waiting";



  /**
   * The suffix for the attribute used to provide the number of successful
   * connection attempts.
   */
  @NotNull private static final String ATTR_SUFFIX_SUCCESSFUL_CONNECTS =
       "pool-num-successful-connection-attempts";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6054649631882735072L;



  // The time the health check information was last updated.
  @Nullable private final Date healthCheckUpdateTime;

  // The health check state for the server.
  @Nullable private final HealthCheckState healthCheckState;

  // The list of health check messages.
  @NotNull private final List<String> healthCheckMessages;

  // The number of add operations attempted.
  @Nullable private final Long addAttempts;

  // The number of failed add operations.
  @Nullable private final Long addFailures;

  // The number of successful add operations.
  @Nullable private final Long addSuccesses;

  // The number of bind operations attempted.
  @Nullable private final Long bindAttempts;

  // The number of failed bind operations.
  @Nullable private final Long bindFailures;

  // The number of available connections in the bind pool.
  @Nullable private final Long bindPoolAvailableConnections;

  // The maximum number of available connections in the bind pool.
  @Nullable private final Long bindPoolMaxAvailableConnections;

  // The number of connections in the bind pool that have been closed as
  // defunct.
  @Nullable private final Long bindPoolNumClosedDefunct;

  // The number of connections in the bind pool that have been closed as
  // expired.
  @Nullable private final Long bindPoolNumClosedExpired;

  // The number of connections in the bind pool that have been closed as
  // unneeded.
  @Nullable private final Long bindPoolNumClosedUnneeded;

  // The number of available failed checkouts in the bind pool.
  @Nullable private final Long bindPoolNumFailedCheckouts;

  // The number of available failed connection attempts in the bind pool.
  @Nullable private final Long bindPoolNumFailedConnectionAttempts;

  // The total number of connections released as valid back to the bind pool.
  @Nullable private final Long bindPoolNumReleasedValid;

  // The total number of successful checkouts from the bind pool.
  @Nullable private final Long bindPoolNumSuccessfulCheckouts;

  // The total number of successful checkouts from the bind pool after waiting
  // for a connection to become available.
  @Nullable private final Long bindPoolNumSuccessfulCheckoutsAfterWaiting;

  // The total number of successful checkouts from the bind pool after creating
  // a new connection.
  @Nullable private final Long bindPoolNumSuccessfulCheckoutsNewConnection;

  // The total number of successful checkouts from the bind pool without waiting
  // for a connection to become available.
  @Nullable private final Long bindPoolNumSuccessfulCheckoutsWithoutWaiting;

  // The number of successful connection attempts in the bind pool.
  @Nullable private final Long bindPoolNumSuccessfulConnectionAttempts;

  // The number of successful bind operations.
  @Nullable private final Long bindSuccesses;

  // The number of available connections in the common pool.
  @Nullable private final Long commonPoolAvailableConnections;

  // The maximum number of available connections in the common pool.
  @Nullable private final Long commonPoolMaxAvailableConnections;

  // The number of connections in the common pool that have been closed as
  // defunct.
  @Nullable private final Long commonPoolNumClosedDefunct;

  // The number of connections in the common pool that have been closed as
  // expired.
  @Nullable private final Long commonPoolNumClosedExpired;

  // The number of connections in the common pool that have been closed as
  // unneeded.
  @Nullable private final Long commonPoolNumClosedUnneeded;

  // The number of available failed checkouts in the common pool.
  @Nullable private final Long commonPoolNumFailedCheckouts;

  // The number of available failed connection attempts in the common pool.
  @Nullable private final Long commonPoolNumFailedConnectionAttempts;

  // The total number of connections released as valid back to the common pool.
  @Nullable private final Long commonPoolNumReleasedValid;

  // The total number of successful checkouts from the common pool.
  @Nullable private final Long commonPoolNumSuccessfulCheckouts;

  // The total number of successful checkouts from the common pool after waiting
  // for a connection to become available.
  @Nullable private final Long commonPoolNumSuccessfulCheckoutsAfterWaiting;

  // The total number of successful checkouts from the common pool after
  // creating a new connection.
  @Nullable private final Long commonPoolNumSuccessfulCheckoutsNewConnection;

  // The total number of successful checkouts from the common pool without
  // waiting for a connection to become available.
  @Nullable private final Long commonPoolNumSuccessfulCheckoutsWithoutWaiting;

  // The number of successful connection attempts in the common pool.
  @Nullable private final Long commonPoolNumSuccessfulConnectionAttempts;

  // The number of compare operations attempted.
  @Nullable private final Long compareAttempts;

  // The number of failed compare operations.
  @Nullable private final Long compareFailures;

  // The number of successful compare operations.
  @Nullable private final Long compareSuccesses;

  // The number of delete operations attempted.
  @Nullable private final Long deleteAttempts;

  // The number of failed delete operations.
  @Nullable private final Long deleteFailures;

  // The number of successful delete operations.
  @Nullable private final Long deleteSuccesses;

  // The health check score for the server.
  @Nullable private final Long healthCheckScore;

  // The number of modify operations attempted.
  @Nullable private final Long modifyAttempts;

  // The number of failed modify operations.
  @Nullable private final Long modifyFailures;

  // The number of successful modify operations.
  @Nullable private final Long modifySuccesses;

  // The number of modify DN operations attempted.
  @Nullable private final Long modifyDNAttempts;

  // The number of failed modify DN operations.
  @Nullable private final Long modifyDNFailures;

  // The number of successful modify DN operations.
  @Nullable private final Long modifyDNSuccesses;

  // The number of available connections in the non-bind pool.
  @Nullable private final Long nonBindPoolAvailableConnections;

  // The maximum number of available connections in the non-bind pool.
  @Nullable private final Long nonBindPoolMaxAvailableConnections;

  // The number of connections in the non-bind pool that have been closed as
  // defunct.
  @Nullable private final Long nonBindPoolNumClosedDefunct;

  // The number of connections in the non-bind pool that have been closed as
  // expired.
  @Nullable private final Long nonBindPoolNumClosedExpired;

  // The number of connections in the non-bind pool that have been closed as
  // unneeded.
  @Nullable private final Long nonBindPoolNumClosedUnneeded;

  // The number of available failed checkouts in the non-bind pool.
  @Nullable private final Long nonBindPoolNumFailedCheckouts;

  // The number of available failed connection attempts in the non-bind pool.
  @Nullable private final Long nonBindPoolNumFailedConnectionAttempts;

  // The total number of connections released as valid back to the non-bind
  // pool.
  @Nullable private final Long nonBindPoolNumReleasedValid;

  // The total number of successful checkouts from the non-bind pool.
  @Nullable private final Long nonBindPoolNumSuccessfulCheckouts;

  // The total number of successful checkouts from the non-bind pool after
  // waiting for a connection to become available.
  @Nullable private final Long nonBindPoolNumSuccessfulCheckoutsAfterWaiting;

  // The total number of successful checkouts from the non-bind pool after
  // creating a new connection.
  @Nullable private final Long nonBindPoolNumSuccessfulCheckoutsNewConnection;

  // The total number of successful checkouts from the non-bind pool without
  // waiting for a connection to become available.
  @Nullable private final Long nonBindPoolNumSuccessfulCheckoutsWithoutWaiting;

  // The number of successful connection attempts in the non-bind pool.
  @Nullable private final Long nonBindPoolNumSuccessfulConnectionAttempts;

  // The number of search operations attempted.
  @Nullable private final Long searchAttempts;

  // The number of failed search operations.
  @Nullable private final Long searchFailures;

  // The number of successful search operations.
  @Nullable private final Long searchSuccesses;

  // The port of the server.
  @Nullable private final Long serverPort;

  // The communication security mechanism used by the server.
  @Nullable private final String communicationSecurity;

  // The DN of the load-balancing algorithm.
  @Nullable private final String loadBalancingAlgorithmDN;

  // The address of the server.
  @Nullable private final String serverAddress;



  /**
   * Creates a new LDAP external server monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as an LDAP external server monitor
   *                entry.  It must not be {@code null}.
   */
  public LDAPExternalServerMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    serverAddress            = getString(ATTR_SERVER_ADDRESS);
    serverPort               = getLong(ATTR_SERVER_PORT);
    communicationSecurity    = getString(ATTR_COMMUNICATION_SECURITY);
    loadBalancingAlgorithmDN = getString(ATTR_LOAD_BALANCING_ALGORITHM_DN);
    healthCheckScore         = getLong(ATTR_HEALTH_CHECK_SCORE);
    healthCheckMessages      = getStrings(ATTR_HEALTH_CHECK_MESSAGE);
    healthCheckUpdateTime    = getDate(ATTR_HEALTH_CHECK_UPDATE_TIME);
    addAttempts              = getLong(ATTR_ADD_ATTEMPTS);
    addFailures              = getLong(ATTR_ADD_FAILURES);
    addSuccesses             = getLong(ATTR_ADD_SUCCESSES);
    bindAttempts             = getLong(ATTR_BIND_ATTEMPTS);
    bindFailures             = getLong(ATTR_BIND_FAILURES);
    bindSuccesses            = getLong(ATTR_BIND_SUCCESSES);
    compareAttempts          = getLong(ATTR_COMPARE_ATTEMPTS);
    compareFailures          = getLong(ATTR_COMPARE_FAILURES);
    compareSuccesses         = getLong(ATTR_COMPARE_SUCCESSES);
    deleteAttempts           = getLong(ATTR_DELETE_ATTEMPTS);
    deleteFailures           = getLong(ATTR_DELETE_FAILURES);
    deleteSuccesses          = getLong(ATTR_DELETE_SUCCESSES);
    modifyAttempts           = getLong(ATTR_MODIFY_ATTEMPTS);
    modifyFailures           = getLong(ATTR_MODIFY_FAILURES);
    modifySuccesses          = getLong(ATTR_MODIFY_SUCCESSES);
    modifyDNAttempts         = getLong(ATTR_MODIFY_DN_ATTEMPTS);
    modifyDNFailures         = getLong(ATTR_MODIFY_DN_FAILURES);
    modifyDNSuccesses        = getLong(ATTR_MODIFY_DN_SUCCESSES);
    searchAttempts           = getLong(ATTR_SEARCH_ATTEMPTS);
    searchFailures           = getLong(ATTR_SEARCH_FAILURES);
    searchSuccesses          = getLong(ATTR_SEARCH_SUCCESSES);

    bindPoolAvailableConnections = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_AVAILABLE_CONNS);
    bindPoolMaxAvailableConnections = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_MAX_AVAILABLE_CONNS);
    bindPoolNumSuccessfulConnectionAttempts = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_SUCCESSFUL_CONNECTS);
    bindPoolNumFailedConnectionAttempts = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_FAILED_CONNECTS);
    bindPoolNumClosedDefunct = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_CLOSED_DEFUNCT);
    bindPoolNumClosedExpired = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_CLOSED_EXPIRED);
    bindPoolNumClosedUnneeded = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_CLOSED_UNNEEDED);
    bindPoolNumSuccessfulCheckouts = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS);
    bindPoolNumSuccessfulCheckoutsWithoutWaiting = getLong(
         ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_WITHOUT_WAITING);
    bindPoolNumSuccessfulCheckoutsAfterWaiting = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_AFTER_WAITING);
    bindPoolNumSuccessfulCheckoutsNewConnection = getLong(
         ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_NEW_CONN);
    bindPoolNumFailedCheckouts = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_FAILED_CHECKOUTS);
    bindPoolNumReleasedValid = getLong(ATTR_PREFIX_BIND_POOL +
         ATTR_SUFFIX_RELEASED_VALID);

    commonPoolAvailableConnections = getLong(ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_AVAILABLE_CONNS);
    commonPoolMaxAvailableConnections = getLong(ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_MAX_AVAILABLE_CONNS);
    commonPoolNumSuccessfulConnectionAttempts = getLong(
         ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_SUCCESSFUL_CONNECTS);
    commonPoolNumFailedConnectionAttempts = getLong(ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_FAILED_CONNECTS);
    commonPoolNumClosedDefunct = getLong(ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_CLOSED_DEFUNCT);
    commonPoolNumClosedExpired = getLong(ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_CLOSED_EXPIRED);
    commonPoolNumClosedUnneeded = getLong(ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_CLOSED_UNNEEDED);
    commonPoolNumSuccessfulCheckouts = getLong(ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS);
    commonPoolNumSuccessfulCheckoutsWithoutWaiting = getLong(
         ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_WITHOUT_WAITING);
    commonPoolNumSuccessfulCheckoutsAfterWaiting = getLong(
         ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_AFTER_WAITING);
    commonPoolNumSuccessfulCheckoutsNewConnection = getLong(
         ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_NEW_CONN);
    commonPoolNumFailedCheckouts = getLong(ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_FAILED_CHECKOUTS);
    commonPoolNumReleasedValid = getLong(ATTR_PREFIX_COMMON_POOL +
         ATTR_SUFFIX_RELEASED_VALID);

    nonBindPoolAvailableConnections = getLong(ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_AVAILABLE_CONNS);
    nonBindPoolMaxAvailableConnections = getLong(ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_MAX_AVAILABLE_CONNS);
    nonBindPoolNumSuccessfulConnectionAttempts = getLong(
         ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_SUCCESSFUL_CONNECTS);
    nonBindPoolNumFailedConnectionAttempts = getLong(ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_FAILED_CONNECTS);
    nonBindPoolNumClosedDefunct = getLong(ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_CLOSED_DEFUNCT);
    nonBindPoolNumClosedExpired = getLong(ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_CLOSED_EXPIRED);
    nonBindPoolNumClosedUnneeded = getLong(ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_CLOSED_UNNEEDED);
    nonBindPoolNumSuccessfulCheckouts = getLong(ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS);
    nonBindPoolNumSuccessfulCheckoutsWithoutWaiting = getLong(
         ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_WITHOUT_WAITING);
    nonBindPoolNumSuccessfulCheckoutsAfterWaiting = getLong(
         ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_AFTER_WAITING);
    nonBindPoolNumSuccessfulCheckoutsNewConnection = getLong(
         ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_NEW_CONN);
    nonBindPoolNumFailedCheckouts = getLong(ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_FAILED_CHECKOUTS);
    nonBindPoolNumReleasedValid = getLong(ATTR_PREFIX_NONBIND_POOL +
         ATTR_SUFFIX_RELEASED_VALID);

    final String hcStateStr = getString(ATTR_HEALTH_CHECK_STATE);
    if (hcStateStr == null)
    {
      healthCheckState = null;
    }
    else
    {
      healthCheckState = HealthCheckState.forName(hcStateStr);
    }
  }



  /**
   * Retrieves the address of the LDAP external server.
   *
   * @return  The address of the LDAP external server, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public String getServerAddress()
  {
    return serverAddress;
  }



  /**
   * Retrieves the port of the LDAP external server.
   *
   * @return  The port of the LDAP external server, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public Long getServerPort()
  {
    return serverPort;
  }



  /**
   * Retrieves the communication security mechanism used when communicating with
   * the external server.
   *
   * @return  The communication security mechanism used when communicating with
   *          the external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public String getCommunicationSecurity()
  {
    return communicationSecurity;
  }



  /**
   * Retrieves the DN of the configuration entry for the load-balancing
   * algorithm that uses the LDAP external server.
   *
   * @return  The DN of the configuration entry for the load-balancing algorithm
   *          that uses the LDAP external server, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getLoadBalancingAlgorithmDN()
  {
    return loadBalancingAlgorithmDN;
  }



  /**
   * Retrieves the health check state for the LDAP external server.
   *
   * @return  The health check state for the LDAP external server, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public HealthCheckState getHealthCheckState()
  {
    return healthCheckState;
  }



  /**
   * Retrieves the health check score for the LDAP external server.
   *
   * @return  The health check score for the LDAP external server, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getHealthCheckScore()
  {
    return healthCheckScore;
  }



  /**
   * Retrieves the list of health check messages for the LDAP external server.
   *
   * @return  The list of health check messages for the LDAP external server, or
   *          an empty list if it was not included in the monitor entry.
   */
  @NotNull()
  public List<String> getHealthCheckMessages()
  {
    return healthCheckMessages;
  }



  /**
   * Retrieves the time the health check information was last updated for the
   * LDAP external server.
   *
   * @return  The time the health check information was last updated for the
   *          LDAP external server, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public Date getHealthCheckUpdateTime()
  {
    return healthCheckUpdateTime;
  }



  /**
   * Retrieves the total number of add operations attempted against the LDAP
   * external server.
   *
   * @return  The total number of add operations attempted against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getAddAttempts()
  {
    return addAttempts;
  }



  /**
   * Retrieves the number of failed add attempts against the LDAP external
   * server.
   *
   * @return  The number of failed add attempts against the LDAP external
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getAddFailures()
  {
    return addFailures;
  }



  /**
   * Retrieves the number of successful add attempts against the LDAP external
   * server.
   *
   * @return  The number of successful add attempts against the LDAP external
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getAddSuccesses()
  {
    return addSuccesses;
  }



  /**
   * Retrieves the total number of bind operations attempted against the LDAP
   * external server.
   *
   * @return  The total number of bind operations attempted against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getBindAttempts()
  {
    return bindAttempts;
  }



  /**
   * Retrieves the number of failed bind attempts against the LDAP external
   * server.
   *
   * @return  The number of failed bind attempts against the LDAP external
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getBindFailures()
  {
    return bindFailures;
  }



  /**
   * Retrieves the number of successful bind attempts against the LDAP external
   * server.
   *
   * @return  The number of successful bind attempts against the LDAP external
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getBindSuccesses()
  {
    return bindSuccesses;
  }



  /**
   * Retrieves the total number of compare operations attempted against the LDAP
   * external server.
   *
   * @return  The total number of compare operations attempted against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getCompareAttempts()
  {
    return compareAttempts;
  }



  /**
   * Retrieves the number of failed compare attempts against the LDAP external
   * server.
   *
   * @return  The number of failed compare attempts against the LDAP external
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getCompareFailures()
  {
    return compareFailures;
  }



  /**
   * Retrieves the number of successful compare attempts against the LDAP
   * external server.
   *
   * @return  The number of successful compare attempts against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getCompareSuccesses()
  {
    return compareSuccesses;
  }



  /**
   * Retrieves the total number of delete operations attempted against the LDAP
   * external server.
   *
   * @return  The total number of delete operations attempted against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getDeleteAttempts()
  {
    return deleteAttempts;
  }



  /**
   * Retrieves the number of failed delete attempts against the LDAP external
   * server.
   *
   * @return  The number of failed delete attempts against the LDAP external
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getDeleteFailures()
  {
    return deleteFailures;
  }



  /**
   * Retrieves the number of successful delete attempts against the LDAP
   * external server.
   *
   * @return  The number of successful delete attempts against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getDeleteSuccesses()
  {
    return deleteSuccesses;
  }



  /**
   * Retrieves the total number of modify operations attempted against the LDAP
   * external server.
   *
   * @return  The total number of modify operations attempted against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getModifyAttempts()
  {
    return modifyAttempts;
  }



  /**
   * Retrieves the number of failed modify attempts against the LDAP external
   * server.
   *
   * @return  The number of failed modify attempts against the LDAP external
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getModifyFailures()
  {
    return modifyFailures;
  }



  /**
   * Retrieves the number of successful modify attempts against the LDAP
   * external server.
   *
   * @return  The number of successful modify attempts against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getModifySuccesses()
  {
    return modifySuccesses;
  }



  /**
   * Retrieves the total number of modify DN operations attempted against the
   * LDAP external server.
   *
   * @return  The total number of modify DN operations attempted against the
   *          LDAP external server, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public Long getModifyDNAttempts()
  {
    return modifyDNAttempts;
  }



  /**
   * Retrieves the number of failed modify DN attempts against the LDAP external
   * server.
   *
   * @return  The number of failed modify DN attempts against the LDAP external
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getModifyDNFailures()
  {
    return modifyDNFailures;
  }



  /**
   * Retrieves the number of successful modify DN attempts against the LDAP
   * external server.
   *
   * @return  The number of successful modify DN attempts against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getModifyDNSuccesses()
  {
    return modifyDNSuccesses;
  }



  /**
   * Retrieves the total number of search operations attempted against the LDAP
   * external server.
   *
   * @return  The total number of search operations attempted against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getSearchAttempts()
  {
    return searchAttempts;
  }



  /**
   * Retrieves the number of failed search attempts against the LDAP external
   * server.
   *
   * @return  The number of failed search attempts against the LDAP external
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getSearchFailures()
  {
    return searchFailures;
  }



  /**
   * Retrieves the number of successful search attempts against the LDAP
   * external server.
   *
   * @return  The number of successful search attempts against the LDAP
   *          external server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getSearchSuccesses()
  {
    return searchSuccesses;
  }



  /**
   * Retrieves the number of currently available connections in the common
   * connection pool used by the LDAP external server used for both bind and
   * non-bind operations.
   *
   * @return  The number of currently available connections in the common
   *          connection pool used by the LDAP external server used for both
   *          bind and non-bind operations, or {@code null} if it was not
   *          included in the monitor entry or if the external server uses
   *          separate pools for bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolAvailableConnections()
  {
    return commonPoolAvailableConnections;
  }



  /**
   * Retrieves the maximum number of connections that may be available in the
   * common connection pool used by the LDAP external server for both bind and
   * non-bind operations.
   *
   * @return  The maximum number of connections that may be available in the
   *          common connection pool used by the LDAP external server for both
   *          bind and non-bind operations, or {@code null} if it was not
   *          included in the monitor entry or if the external server uses
   *          separate pools for bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolMaxAvailableConnections()
  {
    return commonPoolMaxAvailableConnections;
  }



  /**
   * Retrieves the number of successful connection attempts in the common
   * connection pool used by the LDAP external server for both bind and non-bind
   * operations.
   *
   * @return  The number of successful connection attempts in the common
   *          connection pool used by the LDAP external server for both bind and
   *          non-bind operations, or {@code null} if it was not included in the
   *          monitor entry or if the external server uses separate pools for
   *          bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolNumSuccessfulConnectionAttempts()
  {
    return commonPoolNumSuccessfulConnectionAttempts;
  }



  /**
   * Retrieves the number of failed connection attempts in the common connection
   * pool used by the LDAP external server for both bind and non-bind
   * operations.
   *
   * @return  The number of failed connection attempts in the common connection
   *          pool used by the LDAP external server for both bind and non-bind
   *          operations, or {@code null} if it was not included in the monitor
   *          entry or if the external server uses separate pools for bind and
   *          non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolNumFailedConnectionAttempts()
  {
    return commonPoolNumFailedConnectionAttempts;
  }



  /**
   * Retrieves the number of connections in the common connection pool used by
   * the LDAP external server for both bind and non-bind operations that have
   * been closed as defunct.
   *
   * @return  The number of connections in the common connection pool used by
   *          the LDAP external server for both bind and non-bind operations
   *          that have been closed as defunct, or {@code null} if it was not
   *          included in the monitor entry or if the external server uses
   *          separate pools for bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolNumClosedDefunct()
  {
    return commonPoolNumClosedDefunct;
  }



  /**
   * Retrieves the number of connections in the common connection pool used by
   * the LDAP external server for processing both bind and non-bind operations
   * that have been closed as expired.
   *
   * @return  The number of connections in the common connection pool used by
   *          the LDAP external server for both bind and non-bind operations
   *          that have been closed as expired, or {@code null} if it was not
   *          included in the monitor entry or if the external server uses
   *          separate pools for bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolNumClosedExpired()
  {
    return commonPoolNumClosedExpired;
  }



  /**
   * Retrieves the number of connections in the common connection pool used by
   * the LDAP external server for both bind and non-bind operations that have
   * been closed as unneeded.
   *
   * @return  The number of connections in the common connection pool used by
   *          the LDAP external server for both bind and non-bind operations
   *          that have been closed as unneeded, or {@code null} if it was not
   *          included in the monitor entry or if the external server uses
   *          separate pools for bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolNumClosedUnneeded()
  {
    return commonPoolNumClosedUnneeded;
  }



  /**
   * Retrieves the total number of successful checkouts from the common
   * connection pool used by the LDAP external server for both bind and non-bind
   * operations.
   *
   * @return  The total number of successful checkouts from the common
   *          connection pool used by the LDAP external server for both bind and
   *          non-bind operations, or {@code null} if it was not included in the
   *          monitor entry or if the external server uses separate pools for
   *          bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolTotalSuccessfulCheckouts()
  {
    return commonPoolNumSuccessfulCheckouts;
  }



  /**
   * Retrieves the number of successful checkouts from the common connection
   * pool used by the LDAP external server for both bind and non-bind operations
   * in which an existing connection was retrieved without needing to wait.
   *
   * @return  The number of successful checkouts from the common connection pool
   *          used by the LDAP external server for both bind and non-bind
   *          operations in which an existing connection was retrieved without
   *          needing to wait, or {@code null} if it was not included in the
   *          monitor entry or if the external server uses separate pools for
   *          bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolNumSuccessfulCheckoutsWithoutWaiting()
  {
    return commonPoolNumSuccessfulCheckoutsWithoutWaiting;
  }



  /**
   * Retrieves the number of successful checkouts from the common connection
   * pool used by the LDAP external server for both bind and non-bind operations
   * in which an existing connection was retrieved after waiting for the
   * connection to become available.
   *
   * @return  The number of successful checkouts from the common connection pool
   *          used by the LDAP external server for both bind and non-bind
   *          operations in which an existing connection was retrieved after
   *          waiting for the connection to become available, or {@code null} if
   *          it was not included in the monitor entry or if the external server
   *          uses separate pools for bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolNumSuccessfulCheckoutsAfterWaiting()
  {
    return commonPoolNumSuccessfulCheckoutsAfterWaiting;
  }



  /**
   * Retrieves the number of successful checkouts from the common connection
   * pool used by the LDAP external server for both bind and non-bind operations
   * in which an existing connection was retrieved after creating a new
   * connection.
   *
   * @return  The number of successful checkouts from the common connection pool
   *          used by the LDAP external server for both bind and non-bind
   *          operations in which an existing connection was retrieved after
   *          creating a new connection, or {@code null} if it was not included
   *          in the monitor entry or if the external server uses separate pools
   *          for bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolNumSuccessfulCheckoutsNewConnection()
  {
    return commonPoolNumSuccessfulCheckoutsNewConnection;
  }



  /**
   * Retrieves the number of failed checkout attempts from the common connection
   * pool used by the LDAP external server for both bind and non-bind
   * operations.
   *
   * @return  The number of failed checkout attempts from the common connection
   *          pool used by the LDAP external server for both bind and non-bind
   *          operations, or {@code null} if it was not included in the monitor
   *          entry or if the external server uses separate pools for bind and
   *          non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolNumFailedCheckouts()
  {
    return commonPoolNumFailedCheckouts;
  }



  /**
   * Retrieves the number of connections released as valid back to the common
   * connection pool used by the LDAP external server for bind and non-bind
   * operations.
   *
   * @return  The number of connections released as valid back to the common
   *          connection pool used by the LDAP external server used for bind and
   *          non-bind operations, or {@code null} if it was not included in the
   *          monitor entry or if the external server uses a separate pools for
   *          bind and non-bind operations.
   */
  @Nullable()
  public Long getCommonPoolNumReleasedValid()
  {
    return commonPoolNumReleasedValid;
  }



  /**
   * Retrieves the number of currently available connections in the bind
   * connection pool used by the LDAP external server.
   *
   * @return  The number of currently available connections in the bind
   *          connection pool used by the LDAP external server, or {@code null}
   *          if it was not included in the monitor entry or if the external
   *          server uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getBindPoolAvailableConnections()
  {
    return bindPoolAvailableConnections;
  }



  /**
   * Retrieves the maximum number of connections that may be available in the
   * bind connection pool used by the LDAP external server.
   *
   * @return  The maximum number of connections that may be available in the
   *          bind connection pool used by the LDAP external server, or
   *          {@code null} if it was not included in the monitor entry or if the
   *          external server uses a common pool for bind and non-bind
   *          operations.
   */
  @Nullable()
  public Long getBindPoolMaxAvailableConnections()
  {
    return bindPoolMaxAvailableConnections;
  }



  /**
   * Retrieves the number of successful connection attempts in the bind
   * connection pool used by the LDAP external server.
   *
   * @return  The number of successful connection attempts in the bind
   *          connection pool used by the LDAP external server, or {@code null}
   *          if it was not included in the monitor entry or if the external
   *          server uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getBindPoolNumSuccessfulConnectionAttempts()
  {
    return bindPoolNumSuccessfulConnectionAttempts;
  }



  /**
   * Retrieves the number of failed connection attempts in the bind connection
   * pool used by the LDAP external server.
   *
   * @return  The number of failed connection attempts in the bind connection
   *          pool used by the LDAP external server, or {@code null} if it was
   *          not included in the monitor entry or if the external server uses a
   *          common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getBindPoolNumFailedConnectionAttempts()
  {
    return bindPoolNumFailedConnectionAttempts;
  }



  /**
   * Retrieves the number of connections in the bind connection pool used by the
   * LDAP external server that have been closed as defunct.
   *
   * @return  The number of connections in the bind connection pool used by the
   *          LDAP external server that have been closed as defunct, or
   *          {@code null} if it was not included in the monitor entry or if the
   *          external server uses a common pool for bind and non-bind
   *          operations.
   */
  @Nullable()
  public Long getBindPoolNumClosedDefunct()
  {
    return bindPoolNumClosedDefunct;
  }



  /**
   * Retrieves the number of connections in the bind connection pool used by the
   * LDAP external server that have been closed as expired.
   *
   * @return  The number of connections in the bind connection pool used by the
   *          LDAP external server that have been closed as expired, or
   *          {@code null} if it was not included in the monitor entry or if the
   *          external server uses a common pool for bind and non-bind
   *          operations.
   */
  @Nullable()
  public Long getBindPoolNumClosedExpired()
  {
    return bindPoolNumClosedExpired;
  }



  /**
   * Retrieves the number of connections in the bind connection pool used by the
   * LDAP external server that have been closed as unneeded.
   *
   * @return  The number of connections in the bind connection pool used by the
   *          LDAP external server that have been closed as unneeded, or
   *          {@code null} if it was not included in the monitor entry or if the
   *          external server uses a common pool for bind and non-bind
   *          operations.
   */
  @Nullable()
  public Long getBindPoolNumClosedUnneeded()
  {
    return bindPoolNumClosedUnneeded;
  }



  /**
   * Retrieves the total number of successful checkouts from the bind connection
   * pool used by the LDAP external server.
   *
   * @return  The total number of successful checkouts from the bind connection
   *          pool used by the LDAP external server, or {@code null} if it was
   *          not included in the monitor entry or if the external server uses a
   *          common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getBindPoolTotalSuccessfulCheckouts()
  {
    return bindPoolNumSuccessfulCheckouts;
  }



  /**
   * Retrieves the number of successful checkouts from the bind connection pool
   * used by the LDAP external server in which an existing connection was
   * retrieved without needing to wait.
   *
   * @return  The number of successful checkouts from the bind connection pool
   *          used by the LDAP external server in which an existing connection
   *          was retrieved without needing to wait, or {@code null} if it was
   *          not included in the monitor entry or if the external server uses a
   *          common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getBindPoolNumSuccessfulCheckoutsWithoutWaiting()
  {
    return bindPoolNumSuccessfulCheckoutsWithoutWaiting;
  }



  /**
   * Retrieves the number of successful checkouts from the bind connection pool
   * used by the LDAP external server in which an existing connection was
   * retrieved after waiting for the connection to become available.
   *
   * @return  The number of successful checkouts from the bind connection pool
   *          used by the LDAP external server in which an existing connection
   *          was retrieved after waiting for the connection to become
   *          available, or {@code null} if it was not included in the monitor
   *          entry or if the external server uses a common pool for bind and
   *          non-bind operations.
   */
  @Nullable()
  public Long getBindPoolNumSuccessfulCheckoutsAfterWaiting()
  {
    return bindPoolNumSuccessfulCheckoutsAfterWaiting;
  }



  /**
   * Retrieves the number of successful checkouts from the bind connection pool
   * used by the LDAP external server in which an existing connection was
   * retrieved after creating a new connection.
   *
   * @return  The number of successful checkouts from the bind connection pool
   *          used by the LDAP external server in which an existing connection
   *          was retrieved after creating a new connection, or {@code null} if
   *          it was not included in the monitor entry or if the external server
   *          uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getBindPoolNumSuccessfulCheckoutsNewConnection()
  {
    return bindPoolNumSuccessfulCheckoutsNewConnection;
  }



  /**
   * Retrieves the number of failed checkout attempts from the bind connection
   * pool used by the LDAP external server.
   *
   * @return  The number of failed checkout attempts from the bind connection
   *          pool used by the LDAP external server, or {@code null} if it was
   *          not included in the monitor entry or if the external server uses a
   *          common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getBindPoolNumFailedCheckouts()
  {
    return bindPoolNumFailedCheckouts;
  }



  /**
   * Retrieves the number of connections released as valid back to the bind
   * connection pool used by the LDAP external server.
   *
   * @return  The number of connections released as valid back to the bind
   *          connection pool used by the LDAP external server, or {@code null}
   *          if it was not included in the monitor entry or if the external
   *          server uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getBindPoolNumReleasedValid()
  {
    return bindPoolNumReleasedValid;
  }



  /**
   * Retrieves the number of currently available connections in the non-bind
   * connection pool used by the LDAP external server.
   *
   * @return  The number of currently available connections in the non-bind
   *          connection pool used by the LDAP external server, or {@code null}
   *          if it was not included in the monitor entry or if the external
   *          server uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getNonBindPoolAvailableConnections()
  {
    return nonBindPoolAvailableConnections;
  }



  /**
   * Retrieves the maximum number of connections that may be available in the
   * non-bind connection pool used by the LDAP external server.
   *
   * @return  The maximum number of connections that may be available in the
   *          non-bind connection pool used by the LDAP external server, or
   *          {@code null} if it was not included in the monitor entry or if the
   *          external server uses a common pool for bind and non-bind
   *          operations.
   */
  @Nullable()
  public Long getNonBindPoolMaxAvailableConnections()
  {
    return nonBindPoolMaxAvailableConnections;
  }



  /**
   * Retrieves the number of successful connection attempts in the non-bind
   * connection pool used by the LDAP external server.
   *
   * @return  The number of successful connection attempts in the non-bind
   *          connection pool used by the LDAP external server, or {@code null}
   *          if it was not included in the monitor entry or if the external
   *          server uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getNonBindPoolNumSuccessfulConnectionAttempts()
  {
    return nonBindPoolNumSuccessfulConnectionAttempts;
  }



  /**
   * Retrieves the number of failed connection attempts in the non-bind
   * connection pool used by the LDAP external server.
   *
   * @return  The number of failed connection attempts in the non-bind
   *          connection pool used by the LDAP external server, or {@code null}
   *          if it was not included in the monitor entry or if the external
   *          server uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getNonBindPoolNumFailedConnectionAttempts()
  {
    return nonBindPoolNumFailedConnectionAttempts;
  }



  /**
   * Retrieves the number of connections in the non-bind connection pool used by
   * the LDAP external server that have been closed as defunct.
   *
   * @return  The number of connections in the non-bind connection pool used by
   *          the LDAP external server that have been closed as defunct, or
   *          {@code null} if it was not included in the monitor entry or if the
   *          external server uses a common pool for bind and non-bind
   *          operations.
   */
  @Nullable()
  public Long getNonBindPoolNumClosedDefunct()
  {
    return nonBindPoolNumClosedDefunct;
  }



  /**
   * Retrieves the number of connections in the non-bind connection pool used by
   * the LDAP external server that have been closed as expired.
   *
   * @return  The number of connections in the non-bind connection pool used by
   *          the LDAP external server that have been closed as expired, or
   *          {@code null} if it was not included in the monitor entry or if the
   *          external server uses a common pool for bind and non-bind
   *          operations.
   */
  @Nullable()
  public Long getNonBindPoolNumClosedExpired()
  {
    return nonBindPoolNumClosedExpired;
  }



  /**
   * Retrieves the number of connections in the non-bind connection pool used by
   * the LDAP external server that have been closed as unneeded.
   *
   * @return  The number of connections in the non-bind connection pool used by
   *          the LDAP external server that have been closed as unneeded, or
   *          {@code null} if it was not included in the monitor entry or if the
   *          external server uses a common pool for bind and non-bind
   *          operations.
   */
  @Nullable()
  public Long getNonBindPoolNumClosedUnneeded()
  {
    return nonBindPoolNumClosedUnneeded;
  }



  /**
   * Retrieves the total number of successful checkouts from the non-bind
   * connection pool used by the LDAP external server.
   *
   * @return  The total number of successful checkouts from the non-bind
   *          connection pool used by the LDAP external server, or {@code null}
   *          if it was not included in the monitor entry or if the external
   *          server uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getNonBindPoolTotalSuccessfulCheckouts()
  {
    return nonBindPoolNumSuccessfulCheckouts;
  }



  /**
   * Retrieves the number of successful checkouts from the non-bind connection
   * pool used by the LDAP external server in which an existing connection was
   * retrieved without needing to wait.
   *
   * @return  The number of successful checkouts from the non-bind connection
   *          pool used by the LDAP external server in which an existing
   *          connection was retrieved without needing to wait, or {@code null}
   *          if it was not included in the monitor entry or if the external
   *          server uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getNonBindPoolNumSuccessfulCheckoutsWithoutWaiting()
  {
    return nonBindPoolNumSuccessfulCheckoutsWithoutWaiting;
  }



  /**
   * Retrieves the number of successful checkouts from the non-bind connection
   * pool used by the LDAP external server in which an existing connection was
   * retrieved after waiting for the connection to become available.
   *
   * @return  The number of successful checkouts from the non-bind connection
   *          pool used by the LDAP external server in which an existing
   *          connection was retrieved after waiting for the connection to
   *          become available, or {@code null} if it was not included in the
   *          monitor entry or if the external server uses a common pool for
   *          bind and non-bind operations.
   */
  @Nullable()
  public Long getNonBindPoolNumSuccessfulCheckoutsAfterWaiting()
  {
    return nonBindPoolNumSuccessfulCheckoutsAfterWaiting;
  }



  /**
   * Retrieves the number of successful checkouts from the non-bind connection
   * pool used by the LDAP external server in which an existing connection was
   * retrieved after creating a new connection.
   *
   * @return  The number of successful checkouts from the non-bind connection
   *          pool used by the LDAP external server in which an existing
   *          connection was retrieved after creating a new connection, or
   *          {@code null} if it was not included in the monitor entry or if the
   *          external server uses a common pool for bind and non-bind
   *          operations.
   */
  @Nullable()
  public Long getNonBindPoolNumSuccessfulCheckoutsNewConnection()
  {
    return nonBindPoolNumSuccessfulCheckoutsNewConnection;
  }



  /**
   * Retrieves the number of failed checkout attempts from the non-bind
   * connection pool used by the LDAP external server.
   *
   * @return  The number of failed checkout attempts from the non-bind
   *          connection pool used by the LDAP external server, or {@code null}
   *          if it was not included in the monitor entry or if the external
   *          server uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getNonBindPoolNumFailedCheckouts()
  {
    return nonBindPoolNumFailedCheckouts;
  }



  /**
   * Retrieves the number of connections released as valid back to the non-bind
   * connection pool used by the LDAP external server.
   *
   * @return  The number of connections released as valid back to the non-bind
   *          connection pool used by the LDAP external server, or {@code null}
   *          if it was not included in the monitor entry or if the external
   *          server uses a common pool for bind and non-bind operations.
   */
  @Nullable()
  public Long getNonBindPoolNumReleasedValid()
  {
    return nonBindPoolNumReleasedValid;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_LDAP_EXT_SERVER_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_LDAP_EXT_SERVER_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(50));

    if (serverAddress != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SERVER_ADDRESS,
           INFO_LDAP_EXT_SERVER_DISPNAME_SERVER_ADDRESS.get(),
           INFO_LDAP_EXT_SERVER_DESC_SERVER_ADDRESS.get(),
           serverAddress);
    }

    if (serverPort != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SERVER_PORT,
           INFO_LDAP_EXT_SERVER_DISPNAME_SERVER_PORT.get(),
           INFO_LDAP_EXT_SERVER_DESC_SERVER_PORT.get(),
           serverPort);
    }

    if (communicationSecurity != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMMUNICATION_SECURITY,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMUNICATION_SECURITY.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMUNICATION_SECURITY.get(),
           communicationSecurity);
    }

    if (loadBalancingAlgorithmDN != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LOAD_BALANCING_ALGORITHM_DN,
           INFO_LDAP_EXT_SERVER_DISPNAME_LOAD_BALANCING_ALGORITHM_DN.get(),
           INFO_LDAP_EXT_SERVER_DESC_LOAD_BALANCING_ALGORITHM_DN.get(),
           loadBalancingAlgorithmDN);
    }

    if (healthCheckState != null)
    {
      addMonitorAttribute(attrs,
           ATTR_HEALTH_CHECK_STATE,
           INFO_LDAP_EXT_SERVER_DISPNAME_HEALTH_CHECK_STATE.get(),
           INFO_LDAP_EXT_SERVER_DESC_HEALTH_CHECK_STATE.get(),
           healthCheckState.getName());
    }

    if (healthCheckScore != null)
    {
      addMonitorAttribute(attrs,
           ATTR_HEALTH_CHECK_SCORE,
           INFO_LDAP_EXT_SERVER_DISPNAME_HEALTH_CHECK_SCORE.get(),
           INFO_LDAP_EXT_SERVER_DESC_HEALTH_CHECK_SCORE.get(),
           healthCheckScore);
    }

    if ((healthCheckMessages != null) && (! healthCheckMessages.isEmpty()))
    {
      addMonitorAttribute(attrs,
           ATTR_HEALTH_CHECK_MESSAGE,
           INFO_LDAP_EXT_SERVER_DISPNAME_HEALTH_CHECK_MESSAGE.get(),
           INFO_LDAP_EXT_SERVER_DESC_HEALTH_CHECK_MESSAGE.get(),
           healthCheckMessages);
    }

    if (healthCheckUpdateTime != null)
    {
      addMonitorAttribute(attrs,
           ATTR_HEALTH_CHECK_UPDATE_TIME,
           INFO_LDAP_EXT_SERVER_DISPNAME_HEALTH_CHECK_UPDATE_TIME.get(),
           INFO_LDAP_EXT_SERVER_DESC_HEALTH_CHECK_UPDATE_TIME.get(),
           healthCheckUpdateTime);
    }

    if (commonPoolAvailableConnections != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_AVAILABLE_CONNS,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_AVAILABLE_CONNS.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_AVAILABLE_CONNS.get(),
           commonPoolAvailableConnections);
    }

    if (commonPoolMaxAvailableConnections != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_MAX_AVAILABLE_CONNS,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_MAX_AVAILABLE_CONNS.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_MAX_AVAILABLE_CONNS.get(),
           commonPoolMaxAvailableConnections);
    }

    if (commonPoolNumSuccessfulConnectionAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_SUCCESSFUL_CONNECTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_CONNECT_SUCCESS.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_CONNECT_SUCCESS.get(),
           commonPoolNumSuccessfulConnectionAttempts);
    }

    if (commonPoolNumFailedConnectionAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_FAILED_CONNECTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_CONNECT_FAILED.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_CONNECT_FAILED.get(),
           commonPoolNumFailedConnectionAttempts);
    }

    if (commonPoolNumClosedDefunct != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_CLOSED_DEFUNCT,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_CLOSED_DEFUNCT.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_CLOSED_DEFUNCT.get(),
           commonPoolNumClosedDefunct);
    }

    if (commonPoolNumClosedExpired != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_CLOSED_EXPIRED,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_CLOSED_EXPIRED.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_CLOSED_EXPIRED.get(),
           commonPoolNumClosedExpired);
    }

    if (commonPoolNumClosedUnneeded != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_CLOSED_UNNEEDED,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_CLOSED_UNNEEDED.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_CLOSED_UNNEEDED.get(),
           commonPoolNumClosedUnneeded);
    }

    if (commonPoolNumSuccessfulCheckouts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_CHECKOUT_SUCCESS.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_CHECKOUT_SUCCESS.get(),
           commonPoolNumSuccessfulCheckouts);
    }

    if (commonPoolNumSuccessfulCheckoutsWithoutWaiting != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL +
                ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_WITHOUT_WAITING,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_CHECKOUT_NO_WAIT.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_CHECKOUT_NO_WAIT.get(),
           commonPoolNumSuccessfulCheckoutsWithoutWaiting);
    }

    if (commonPoolNumSuccessfulCheckoutsAfterWaiting != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL +
                ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_AFTER_WAITING,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_CHECKOUT_WITH_WAIT.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_CHECKOUT_WITH_WAIT.get(),
           commonPoolNumSuccessfulCheckoutsAfterWaiting);
    }

    if (commonPoolNumSuccessfulCheckoutsNewConnection != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL +
                ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_NEW_CONN,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_CHECKOUT_NEW_CONN.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_CHECKOUT_NEW_CONN.get(),
           commonPoolNumSuccessfulCheckoutsNewConnection);
    }

    if (commonPoolNumFailedCheckouts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_FAILED_CHECKOUTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_CHECKOUT_FAILED.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_CHECKOUT_FAILED.get(),
           commonPoolNumFailedCheckouts);
    }

    if (commonPoolNumReleasedValid != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_COMMON_POOL + ATTR_SUFFIX_RELEASED_VALID,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMMON_RELEASED_VALID.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMMON_RELEASED_VALID.get(),
           commonPoolNumReleasedValid);
    }

    if (bindPoolAvailableConnections != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_AVAILABLE_CONNS,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_AVAILABLE_CONNS.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_AVAILABLE_CONNS.get(),
           bindPoolAvailableConnections);
    }

    if (bindPoolMaxAvailableConnections != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_MAX_AVAILABLE_CONNS,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_MAX_AVAILABLE_CONNS.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_MAX_AVAILABLE_CONNS.get(),
           bindPoolMaxAvailableConnections);
    }

    if (bindPoolNumSuccessfulConnectionAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_SUCCESSFUL_CONNECTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_CONNECT_SUCCESS.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_CONNECT_SUCCESS.get(),
           bindPoolNumSuccessfulConnectionAttempts);
    }

    if (bindPoolNumFailedConnectionAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_FAILED_CONNECTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_CONNECT_FAILED.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_CONNECT_FAILED.get(),
           bindPoolNumFailedConnectionAttempts);
    }

    if (bindPoolNumClosedDefunct != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_CLOSED_DEFUNCT,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_CLOSED_DEFUNCT.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_CLOSED_DEFUNCT.get(),
           bindPoolNumClosedDefunct);
    }

    if (bindPoolNumClosedExpired != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_CLOSED_EXPIRED,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_CLOSED_EXPIRED.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_CLOSED_EXPIRED.get(),
           bindPoolNumClosedExpired);
    }

    if (bindPoolNumClosedUnneeded != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_CLOSED_UNNEEDED,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_CLOSED_UNNEEDED.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_CLOSED_UNNEEDED.get(),
           bindPoolNumClosedUnneeded);
    }

    if (bindPoolNumSuccessfulCheckouts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_CHECKOUT_SUCCESS.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_CHECKOUT_SUCCESS.get(),
           bindPoolNumSuccessfulCheckouts);
    }

    if (bindPoolNumSuccessfulCheckoutsWithoutWaiting != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL +
                ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_WITHOUT_WAITING,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_CHECKOUT_NO_WAIT.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_CHECKOUT_NO_WAIT.get(),
           bindPoolNumSuccessfulCheckoutsWithoutWaiting);
    }

    if (bindPoolNumSuccessfulCheckoutsAfterWaiting != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL +
                ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_AFTER_WAITING,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_CHECKOUT_WITH_WAIT.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_CHECKOUT_WITH_WAIT.get(),
           bindPoolNumSuccessfulCheckoutsAfterWaiting);
    }

    if (bindPoolNumSuccessfulCheckoutsNewConnection != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL +
                ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_NEW_CONN,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_CHECKOUT_NEW_CONN.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_CHECKOUT_NEW_CONN.get(),
           bindPoolNumSuccessfulCheckoutsNewConnection);
    }

    if (bindPoolNumFailedCheckouts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_FAILED_CHECKOUTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_CHECKOUT_FAILED.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_CHECKOUT_FAILED.get(),
           bindPoolNumFailedCheckouts);
    }

    if (bindPoolNumReleasedValid != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_BIND_POOL + ATTR_SUFFIX_RELEASED_VALID,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_RELEASED_VALID.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_RELEASED_VALID.get(),
           bindPoolNumReleasedValid);
    }

    if (nonBindPoolAvailableConnections != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_AVAILABLE_CONNS,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_AVAILABLE_CONNS.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_AVAILABLE_CONNS.get(),
           nonBindPoolAvailableConnections);
    }

    if (nonBindPoolMaxAvailableConnections != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_MAX_AVAILABLE_CONNS,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_MAX_AVAILABLE_CONNS.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_MAX_AVAILABLE_CONNS.get(),
           nonBindPoolMaxAvailableConnections);
    }

    if (nonBindPoolNumSuccessfulConnectionAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_SUCCESSFUL_CONNECTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_CONNECT_SUCCESS.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_CONNECT_SUCCESS.get(),
           nonBindPoolNumSuccessfulConnectionAttempts);
    }

    if (nonBindPoolNumFailedConnectionAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_FAILED_CONNECTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_CONNECT_FAILED.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_CONNECT_FAILED.get(),
           nonBindPoolNumFailedConnectionAttempts);
    }

    if (nonBindPoolNumClosedDefunct != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_CLOSED_DEFUNCT,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_CLOSED_DEFUNCT.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_CLOSED_DEFUNCT.get(),
           nonBindPoolNumClosedDefunct);
    }

    if (nonBindPoolNumClosedExpired != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_CLOSED_EXPIRED,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_CLOSED_EXPIRED.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_CLOSED_EXPIRED.get(),
           nonBindPoolNumClosedExpired);
    }

    if (nonBindPoolNumClosedUnneeded != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_CLOSED_UNNEEDED,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_CLOSED_UNNEEDED.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_CLOSED_UNNEEDED.get(),
           nonBindPoolNumClosedUnneeded);
    }

    if (nonBindPoolNumSuccessfulCheckouts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_CHECKOUT_SUCCESS.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_CHECKOUT_SUCCESS.get(),
           nonBindPoolNumSuccessfulCheckouts);
    }

    if (nonBindPoolNumSuccessfulCheckoutsWithoutWaiting != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL +
                ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_WITHOUT_WAITING,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_CHECKOUT_NO_WAIT.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_CHECKOUT_NO_WAIT.get(),
           nonBindPoolNumSuccessfulCheckoutsWithoutWaiting);
    }

    if (nonBindPoolNumSuccessfulCheckoutsAfterWaiting != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL +
                ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_AFTER_WAITING,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_CHECKOUT_WITH_WAIT.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_CHECKOUT_WITH_WAIT.get(),
           nonBindPoolNumSuccessfulCheckoutsAfterWaiting);
    }

    if (nonBindPoolNumSuccessfulCheckoutsNewConnection != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL +
                ATTR_SUFFIX_SUCCESSFUL_CHECKOUTS_NEW_CONN,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_CHECKOUT_NEW_CONN.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_CHECKOUT_NEW_CONN.get(),
           nonBindPoolNumSuccessfulCheckoutsNewConnection);
    }

    if (nonBindPoolNumFailedCheckouts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_FAILED_CHECKOUTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_CHECKOUT_FAILED.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_CHECKOUT_FAILED.get(),
           nonBindPoolNumFailedCheckouts);
    }

    if (nonBindPoolNumReleasedValid != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PREFIX_NONBIND_POOL + ATTR_SUFFIX_RELEASED_VALID,
           INFO_LDAP_EXT_SERVER_DISPNAME_NONBIND_RELEASED_VALID.get(),
           INFO_LDAP_EXT_SERVER_DESC_NONBIND_RELEASED_VALID.get(),
           nonBindPoolNumReleasedValid);
    }

    if (addAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ADD_ATTEMPTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_ADD_ATTEMPTS.get(),
           INFO_LDAP_EXT_SERVER_DESC_ADD_ATTEMPTS.get(),
           addAttempts);
    }

    if (addFailures != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ADD_FAILURES,
           INFO_LDAP_EXT_SERVER_DISPNAME_ADD_FAILURES.get(),
           INFO_LDAP_EXT_SERVER_DESC_ADD_FAILURES.get(),
           addFailures);
    }

    if (addSuccesses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ADD_SUCCESSES,
           INFO_LDAP_EXT_SERVER_DISPNAME_ADD_SUCCESSES.get(),
           INFO_LDAP_EXT_SERVER_DESC_ADD_SUCCESSES.get(),
           addSuccesses);
    }

    if (bindAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BIND_ATTEMPTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_ATTEMPTS.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_ATTEMPTS.get(),
           bindAttempts);
    }

    if (bindFailures != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BIND_FAILURES,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_FAILURES.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_FAILURES.get(),
           bindFailures);
    }

    if (bindSuccesses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BIND_SUCCESSES,
           INFO_LDAP_EXT_SERVER_DISPNAME_BIND_SUCCESSES.get(),
           INFO_LDAP_EXT_SERVER_DESC_BIND_SUCCESSES.get(),
           bindSuccesses);
    }

    if (compareAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMPARE_ATTEMPTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMPARE_ATTEMPTS.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMPARE_ATTEMPTS.get(),
           compareAttempts);
    }

    if (compareFailures != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMPARE_FAILURES,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMPARE_FAILURES.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMPARE_FAILURES.get(),
           compareFailures);
    }

    if (compareSuccesses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMPARE_SUCCESSES,
           INFO_LDAP_EXT_SERVER_DISPNAME_COMPARE_SUCCESSES.get(),
           INFO_LDAP_EXT_SERVER_DESC_COMPARE_SUCCESSES.get(),
           compareSuccesses);
    }

    if (deleteAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DELETE_ATTEMPTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_DELETE_ATTEMPTS.get(),
           INFO_LDAP_EXT_SERVER_DESC_DELETE_ATTEMPTS.get(),
           deleteAttempts);
    }

    if (deleteFailures != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DELETE_FAILURES,
           INFO_LDAP_EXT_SERVER_DISPNAME_DELETE_FAILURES.get(),
           INFO_LDAP_EXT_SERVER_DESC_DELETE_FAILURES.get(),
           deleteFailures);
    }

    if (deleteSuccesses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DELETE_SUCCESSES,
           INFO_LDAP_EXT_SERVER_DISPNAME_DELETE_SUCCESSES.get(),
           INFO_LDAP_EXT_SERVER_DESC_DELETE_SUCCESSES.get(),
           deleteSuccesses);
    }

    if (modifyAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_ATTEMPTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_MODIFY_ATTEMPTS.get(),
           INFO_LDAP_EXT_SERVER_DESC_MODIFY_ATTEMPTS.get(),
           modifyAttempts);
    }

    if (modifyFailures != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_FAILURES,
           INFO_LDAP_EXT_SERVER_DISPNAME_MODIFY_FAILURES.get(),
           INFO_LDAP_EXT_SERVER_DESC_MODIFY_FAILURES.get(),
           modifyFailures);
    }

    if (modifySuccesses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_SUCCESSES,
           INFO_LDAP_EXT_SERVER_DISPNAME_MODIFY_SUCCESSES.get(),
           INFO_LDAP_EXT_SERVER_DESC_MODIFY_SUCCESSES.get(),
           modifySuccesses);
    }

    if (modifyDNAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_DN_ATTEMPTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_MODIFY_DN_ATTEMPTS.get(),
           INFO_LDAP_EXT_SERVER_DESC_MODIFY_DN_ATTEMPTS.get(),
           modifyDNAttempts);
    }

    if (modifyDNFailures != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_DN_FAILURES,
           INFO_LDAP_EXT_SERVER_DISPNAME_MODIFY_DN_FAILURES.get(),
           INFO_LDAP_EXT_SERVER_DESC_MODIFY_DN_FAILURES.get(),
           modifyDNFailures);
    }

    if (modifyDNSuccesses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_DN_SUCCESSES,
           INFO_LDAP_EXT_SERVER_DISPNAME_MODIFY_DN_SUCCESSES.get(),
           INFO_LDAP_EXT_SERVER_DESC_MODIFY_DN_SUCCESSES.get(),
           modifyDNSuccesses);
    }

    if (searchAttempts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_ATTEMPTS,
           INFO_LDAP_EXT_SERVER_DISPNAME_SEARCH_ATTEMPTS.get(),
           INFO_LDAP_EXT_SERVER_DESC_SEARCH_ATTEMPTS.get(),
           searchAttempts);
    }

    if (searchFailures != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_FAILURES,
           INFO_LDAP_EXT_SERVER_DISPNAME_SEARCH_FAILURES.get(),
           INFO_LDAP_EXT_SERVER_DESC_SEARCH_FAILURES.get(),
           searchFailures);
    }

    if (searchSuccesses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_SUCCESSES,
           INFO_LDAP_EXT_SERVER_DISPNAME_SEARCH_SUCCESSES.get(),
           INFO_LDAP_EXT_SERVER_DESC_SEARCH_SUCCESSES.get(),
           searchSuccesses);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
