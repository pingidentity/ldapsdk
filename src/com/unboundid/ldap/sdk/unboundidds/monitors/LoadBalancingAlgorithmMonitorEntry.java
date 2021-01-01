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



import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about a
 * load-balancing algorithm used by the Directory Proxy Server.
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
 *   <LI>The aggregate health check state for servers associated with the
 *       load-balancing algorithm.</LI>
 *   <LI>Information about each server associated with the load-balancing
 *       algorithm, including the address, port, and health check state for the
 *       server.</LI>
 *   <LI>The number of available, degraded, and unavailable servers associated
 *       with the load-balancing algorithm.</LI>
 * </UL>
 * The server should present a load-balancing algorithm monitor entry for each
 * load-balancing algorithm used by a proxying request processor.  These entries
 * can be retrieved using the
 * {@link MonitorManager#getLoadBalancingAlgorithmMonitorEntries} method.  These
 * entries provide specific methods for accessing this information.
 * Alternately, the information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LoadBalancingAlgorithmMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in LDAP external server monitor entries.
   */
  @NotNull protected static final String LOAD_BALANCING_ALGORITHM_MONITOR_OC =
       "ds-load-balancing-algorithm-monitor-entry";



  /**
   * The name of the attribute used to provide the name of the load-balancing
   * algorithm.
   */
  @NotNull private static final String ATTR_ALGORITHM_NAME = "algorithm-name";



  /**
   * The name of the attribute used to provide the DN of the configuration entry
   * for the load-balancing algorithm.
   */
  @NotNull private static final String ATTR_CONFIG_ENTRY_DN = "config-entry-dn";



  /**
   * The name of the attribute used to provide the aggregate health check state
   * for the load-balancing algorithm.
   */
  @NotNull private static final String ATTR_HEALTH_CHECK_STATE =
       "health-check-state";



  /**
   * The name of the attribute used to provide information about the health
   * check states of each of the LDAP external servers associated with the
   * load-balancing algorithm.
   */
  @NotNull private static final String ATTR_LDAP_EXTERNAL_SERVER =
       "ldap-external-server";



  /**
   * The name of the attribute used to provide the aggregate health check state
   * for local servers for the load-balancing algorithm.
   */
  @NotNull private static final String ATTR_LOCAL_SERVERS_HEALTH_CHECK_STATE =
       "local-servers-health-check-state";



  /**
   * The name of the attribute used to provide the aggregate health check state
   * for non-local servers for the load-balancing algorithm.
   */
  @NotNull private static final String
       ATTR_NON_LOCAL_SERVERS_HEALTH_CHECK_STATE =
            "non-local-servers-health-check-state";



  /**
   * The name of the attribute used to provide the number of servers associated
   * with the load-balancing algorithm with a health check state of AVAILABLE.
   */
  @NotNull private static final String ATTR_NUM_AVAILABLE =
       "num-available-servers";



  /**
   * The name of the attribute used to provide the number of servers associated
   * with the load-balancing algorithm with a health check state of DEGRADED.
   */
  @NotNull private static final String ATTR_NUM_DEGRADED =
       "num-degraded-servers";



  /**
   * The name of the attribute used to provide the number of servers associated
   * with the load-balancing algorithm with a health check state of UNAVAILABLE.
   */
  @NotNull private static final String ATTR_NUM_UNAVAILABLE =
       "num-unavailable-servers";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5251924301718025205L;



  // The aggregate health check state for the load-balancing algorithm.
  @Nullable private final HealthCheckState healthCheckState;

  // The aggregate health check state for local servers for the load-balancing
  // algorithm.
  @Nullable private final HealthCheckState localServersHealthCheckState;

  // The aggregate health check state for non-local servers for the
  // load-balancing algorithm.
  @Nullable private final HealthCheckState nonLocalServersHealthCheckState;

  // The list of server availability objects.
  @NotNull private final List<LoadBalancingAlgorithmServerAvailabilityData>
       serverAvailabilityData;

  // The number of servers with a health check state of AVAILABLE.
  @Nullable private final Long numAvailableServers;

  // The number of servers with a health check state of DEGRADED.
  @Nullable private final Long numDegradedServers;

  // The number of servers with a health check state of UNAVAILABLE.
  @Nullable private final Long numUnavailableServers;

  // The name of the load-balancing algorithm.
  @Nullable private final String algorithmName;

  // The DN of the configuration entry for the load-balancing algorithm.
  @Nullable private final String configEntryDN;



  /**
   * Creates a new load-balancing algorithm monitor entry from the provided
   * entry.
   *
   * @param  entry  The entry to be parsed as a load-balancing algorithm monitor
   *                entry.  It must not be {@code null}.
   */
  public LoadBalancingAlgorithmMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    algorithmName = getString(ATTR_ALGORITHM_NAME);
    configEntryDN = getString(ATTR_CONFIG_ENTRY_DN);
    numAvailableServers = getLong(ATTR_NUM_AVAILABLE);
    numDegradedServers = getLong(ATTR_NUM_DEGRADED);
    numUnavailableServers = getLong(ATTR_NUM_UNAVAILABLE);

    final String hcStateStr = getString(ATTR_HEALTH_CHECK_STATE);
    if (hcStateStr == null)
    {
      healthCheckState = null;
    }
    else
    {
      healthCheckState = HealthCheckState.forName(hcStateStr);
    }

    final String localHCStateStr =
         getString(ATTR_LOCAL_SERVERS_HEALTH_CHECK_STATE);
    if (localHCStateStr == null)
    {
      localServersHealthCheckState = null;
    }
    else
    {
      localServersHealthCheckState = HealthCheckState.forName(localHCStateStr);
    }

    final String nonLocalHCStateStr =
         getString(ATTR_NON_LOCAL_SERVERS_HEALTH_CHECK_STATE);
    if (nonLocalHCStateStr == null)
    {
      nonLocalServersHealthCheckState = null;
    }
    else
    {
      nonLocalServersHealthCheckState =
           HealthCheckState.forName(nonLocalHCStateStr);
    }

    final List<String> externalServerStrings =
         getStrings(ATTR_LDAP_EXTERNAL_SERVER);
    final ArrayList<LoadBalancingAlgorithmServerAvailabilityData> serverData =
         new ArrayList<>(externalServerStrings.size());
    for (final String s : externalServerStrings)
    {
      try
      {
        serverData.add(new LoadBalancingAlgorithmServerAvailabilityData(s));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
    serverAvailabilityData = Collections.unmodifiableList(serverData);
  }



  /**
   * Retrieves the name of the load-balancing algorithm.
   *
   * @return  The name of the load-balancing algorithm, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public String getAlgorithmName()
  {
    return algorithmName;
  }



  /**
   * Retrieves the DN of the configuration entry for the load-balancing
   * algorithm.
   *
   * @return  The DN of the configuration entry for the load-balancing
   *          algorithm, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public String getConfigEntryDN()
  {
    return configEntryDN;
  }



  /**
   * Retrieves the aggregate health check state for the load-balancing
   * algorithm.
   *
   * @return  The aggregate health check state for the load-balancing algorithm,
   *          or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public HealthCheckState getHealthCheckState()
  {
    return healthCheckState;
  }



  /**
   * Retrieves the aggregate health check state for local servers for the
   * load-balancing algorithm.
   *
   * @return  The aggregate health check state for local servers for the
   *          load-balancing algorithm, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public HealthCheckState getLocalServersHealthCheckState()
  {
    return localServersHealthCheckState;
  }



  /**
   * Retrieves the aggregate health check state for non-local servers for the
   * load-balancing algorithm.
   *
   * @return  The aggregate health check state for non-local servers for the
   *          load-balancing algorithm, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public HealthCheckState getNonLocalServersHealthCheckState()
  {
    return nonLocalServersHealthCheckState;
  }



  /**
   * Retrieves a list with information about the healths of the individual LDAP
   * external servers associated with the load-balancing algorithm.
   *
   * @return  A list with information about the healths of the individual LDAP
   *          external servers associated with the load-balancing algorithm, or
   *          an empty list if it was not included in the monitor entry.
   */
  @NotNull()
  public List<LoadBalancingAlgorithmServerAvailabilityData>
              getServerAvailabilityData()
  {
    return serverAvailabilityData;
  }



  /**
   * Retrieves the number of servers associated with the load-balancing
   * algorithm that have a health check state of AVAILABLE.
   *
   * @return  The number of servers associated with the load-balancing algorithm
   *          that have a health check state of AVAILABLE, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getNumAvailableServers()
  {
    return numAvailableServers;
  }



  /**
   * Retrieves the number of servers associated with the load-balancing
   * algorithm that have a health check state of DEGRADED.
   *
   * @return  The number of servers associated with the load-balancing algorithm
   *          that have a health check state of DEGRADED, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getNumDegradedServers()
  {
    return numDegradedServers;
  }



  /**
   * Retrieves the number of servers associated with the load-balancing
   * algorithm that have a health check state of UNAVAILABLE.
   *
   * @return  The number of servers associated with the load-balancing algorithm
   *          that have a health check state of UNAVAILABLE, or {@code null} if
   *          it was not included in the monitor entry.
   */
  @Nullable()
  public Long getNumUnavailableServers()
  {
    return numUnavailableServers;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_LOAD_BALANCING_ALGORITHM_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_LOAD_BALANCING_ALGORITHM_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(9));

    if (algorithmName != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ALGORITHM_NAME,
           INFO_LOAD_BALANCING_ALGORITHM_DISPNAME_ALGORITHM_NAME.get(),
           INFO_LOAD_BALANCING_ALGORITHM_DESC_ALGORITHM_NAME.get(),
           algorithmName);
    }

    if (configEntryDN != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CONFIG_ENTRY_DN,
           INFO_LOAD_BALANCING_ALGORITHM_DISPNAME_CONFIG_ENTRY_DN.get(),
           INFO_LOAD_BALANCING_ALGORITHM_DESC_CONFIG_ENTRY_DN.get(),
           configEntryDN);
    }

    if (healthCheckState != null)
    {
      addMonitorAttribute(attrs,
           ATTR_HEALTH_CHECK_STATE,
           INFO_LOAD_BALANCING_ALGORITHM_DISPNAME_HEALTH_CHECK_STATE.get(),
           INFO_LOAD_BALANCING_ALGORITHM_DESC_HEALTH_CHECK_STATE.get(),
           healthCheckState.name());
    }

    if (localServersHealthCheckState != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LOCAL_SERVERS_HEALTH_CHECK_STATE,
           INFO_LOAD_BALANCING_ALGORITHM_DISPNAME_L_HEALTH_CHECK_STATE.get(),
           INFO_LOAD_BALANCING_ALGORITHM_DESC_L_HEALTH_CHECK_STATE.get(),
           localServersHealthCheckState.name());
    }

    if (nonLocalServersHealthCheckState != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NON_LOCAL_SERVERS_HEALTH_CHECK_STATE,
           INFO_LOAD_BALANCING_ALGORITHM_DISPNAME_NL_HEALTH_CHECK_STATE.get(),
           INFO_LOAD_BALANCING_ALGORITHM_DESC_NL_HEALTH_CHECK_STATE.get(),
           nonLocalServersHealthCheckState.name());
    }

    if ((serverAvailabilityData != null) &&
        (! serverAvailabilityData.isEmpty()))
    {
      final ArrayList<String> availabilityStrings =
           new ArrayList<>(serverAvailabilityData.size());
      for (final LoadBalancingAlgorithmServerAvailabilityData d :
           serverAvailabilityData)
      {
        availabilityStrings.add(d.toCompactString());
      }
      addMonitorAttribute(attrs,
           ATTR_LDAP_EXTERNAL_SERVER,
           INFO_LOAD_BALANCING_ALGORITHM_DISPNAME_SERVER_DATA.get(),
           INFO_LOAD_BALANCING_ALGORITHM_DESC_SERVER_DATA.get(),
           availabilityStrings);
    }

    if (numAvailableServers != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_AVAILABLE,
           INFO_LOAD_BALANCING_ALGORITHM_DISPNAME_NUM_AVAILABLE.get(),
           INFO_LOAD_BALANCING_ALGORITHM_DESC_NUM_AVAILABLE.get(),
           numAvailableServers);
    }

    if (numDegradedServers != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_DEGRADED,
           INFO_LOAD_BALANCING_ALGORITHM_DISPNAME_NUM_DEGRADED.get(),
           INFO_LOAD_BALANCING_ALGORITHM_DESC_NUM_DEGRADED.get(),
           numDegradedServers);
    }

    if (numUnavailableServers != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_UNAVAILABLE,
           INFO_LOAD_BALANCING_ALGORITHM_DISPNAME_NUM_UNAVAILABLE.get(),
           INFO_LOAD_BALANCING_ALGORITHM_DESC_NUM_UNAVAILABLE.get(),
           numUnavailableServers);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
