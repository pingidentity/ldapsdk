/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
import java.util.List;
import java.util.logging.Level;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.DebugType;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;



/**
 * This class provides a set of methods for retrieving Directory Server monitor
 * entries.  In particular, it provides methods for retrieving all monitor
 * entries from the server, as well as retrieving monitor entries of specific
 * types.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for retrieving all monitor
 * entries published by the directory server and printing the information
 * contained in each using the generic API for accessing monitor entry data:
 * <PRE>
 * List&lt;MonitorEntry&gt; allMonitorEntries =
 *      MonitorManager.getMonitorEntries(connection);
 * for (MonitorEntry e : allMonitorEntries)
 * {
 *   String monitorName = e.getMonitorName();
 *   String displayName = e.getMonitorDisplayName();
 *   Map&lt;String,MonitorAttribute&gt; monitorAttributes =
 *        e.getMonitorAttributes();
 * }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MonitorManager
{
  /**
   * Prevent this class from being instantiated.
   */
  private MonitorManager()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a list of all monitor entries available in the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all monitor entries available in the Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<MonitorEntry> getMonitorEntries(
                                        final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves a list of all monitor entries available in the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all monitor entries available in the Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<MonitorEntry> getMonitorEntries(
                                        final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         MonitorEntry.GENERIC_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<MonitorEntry> monitorEntries =
         new ArrayList<MonitorEntry>(searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(MonitorEntry.decode(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves the general monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The general monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static GeneralMonitorEntry getGeneralMonitorEntry(
                                         final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getGeneralMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the general monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The general monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static GeneralMonitorEntry getGeneralMonitorEntry(
                                         final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createPresenceFilter("objectClass");

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.BASE,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getGeneralMonitorEntry");

      return null;
    }

    return new GeneralMonitorEntry(searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves the active operations monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The active operations monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static ActiveOperationsMonitorEntry
                     getActiveOperationsMonitorEntry(
                          final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getActiveOperationsMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the active operations monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The active operations monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static ActiveOperationsMonitorEntry
                     getActiveOperationsMonitorEntry(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         ActiveOperationsMonitorEntry.ACTIVE_OPERATIONS_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getActiveOperationsMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getActiveOperationsMonitorEntry");
    }

    return new ActiveOperationsMonitorEntry(
                    searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves a list of all backend monitor entries available in the Directory
   * Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all backend monitor entries available in the Directory
   *          Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<BackendMonitorEntry> getBackendMonitorEntries(
                                               final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getBackendMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves a list of all backend monitor entries available in the Directory
   * Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all backend monitor entries available in the Directory
   *          Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<BackendMonitorEntry> getBackendMonitorEntries(
                                               final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         BackendMonitorEntry.BACKEND_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<BackendMonitorEntry> monitorEntries =
         new ArrayList<BackendMonitorEntry>(searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new BackendMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves the client connection monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The client connection monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static ClientConnectionMonitorEntry
                     getClientConnectionMonitorEntry(
                          final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getClientConnectionMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the client connection monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The client connection monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static ClientConnectionMonitorEntry
                     getClientConnectionMonitorEntry(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         ClientConnectionMonitorEntry.CLIENT_CONNECTION_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getClientConnectionMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getClientConnectionMonitorEntry");
    }

    return new ClientConnectionMonitorEntry(
                    searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves a list of all connection handler monitor entries available in the
   * Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all connection handler monitor entries available in the
   *          Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<ConnectionHandlerMonitorEntry>
                     getConnectionHandlerMonitorEntries(
                          final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getConnectionHandlerMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves a list of all connection handler monitor entries available in the
   * Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all connection handler monitor entries available in the
   *          Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<ConnectionHandlerMonitorEntry>
                     getConnectionHandlerMonitorEntries(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         ConnectionHandlerMonitorEntry.CONNECTION_HANDLER_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<ConnectionHandlerMonitorEntry> monitorEntries =
         new ArrayList<ConnectionHandlerMonitorEntry>(
                  searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new ConnectionHandlerMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves the disk space usage monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The disk space usage monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static DiskSpaceUsageMonitorEntry getDiskSpaceUsageMonitorEntry(
                                                final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getDiskSpaceUsageMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the disk space usage monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The disk space usage monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static DiskSpaceUsageMonitorEntry getDiskSpaceUsageMonitorEntry(
                                                final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         DiskSpaceUsageMonitorEntry.DISK_SPACE_USAGE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getDiskSpaceUsageMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getDiskSpaceUsageMonitorEntry");
    }

    return new DiskSpaceUsageMonitorEntry(
                    searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves the entry cache monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The entry cache monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static EntryCacheMonitorEntry getEntryCacheMonitorEntry(
                                            final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getEntryCacheMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the entry cache monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The entry cache monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static EntryCacheMonitorEntry getEntryCacheMonitorEntry(
                                            final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         EntryCacheMonitorEntry.ENTRY_CACHE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getEntryCacheMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getEntryCacheMonitorEntry");
    }

    return new EntryCacheMonitorEntry(searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves the FIFO entry cache monitor entries from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The entry cache monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<FIFOEntryCacheMonitorEntry>
              getFIFOEntryCacheMonitorEntries(final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getFIFOEntryCacheMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves the FIFO entry cache monitor entries from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The entry cache monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<FIFOEntryCacheMonitorEntry>
              getFIFOEntryCacheMonitorEntries(final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         FIFOEntryCacheMonitorEntry.FIFO_ENTRY_CACHE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<FIFOEntryCacheMonitorEntry> monitorEntries =
         new ArrayList<FIFOEntryCacheMonitorEntry>(
              searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new FIFOEntryCacheMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves a list of all gauge monitor entries available in the Directory
   * Server.  This may include monitor entries for gauges of different types
   * (e.g., numeric gauges and indicator gauges).
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all gauge monitor entries available in the Directory
   *          Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<GaugeMonitorEntry> getGaugeMonitorEntries(
                                             final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         GaugeMonitorEntry.GAUGE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<GaugeMonitorEntry> monitorEntries =
         new ArrayList<GaugeMonitorEntry>(searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      try
      {
        monitorEntries.add((GaugeMonitorEntry) MonitorEntry.decode(e));
      }
      catch (final Exception ex)
      {
        debugException(ex);
      }
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves the group cache monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The group cache monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static GroupCacheMonitorEntry getGroupCacheMonitorEntry(
                                            final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         GroupCacheMonitorEntry.GROUP_CACHE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getGroupCacheMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getGroupCacheMonitorEntry");
    }

    return new GroupCacheMonitorEntry(searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves the host system recent CPU and memory monitor entry from the
   * Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The host system recent CPU and memory monitor entry from the
   *          Directory Server, or {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static HostSystemRecentCPUAndMemoryMonitorEntry
                     getHostSystemRecentCPUAndMemoryMonitorEntry(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         HostSystemRecentCPUAndMemoryMonitorEntry.
              HOST_SYSTEM_RECENT_CPU_AND_MEMORY_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in " +
                 "getHostSystemRecentCPUAndMemoryMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in " +
                 "getHostSystemRecentCPUAndMemoryMonitorEntry");
    }

    return new HostSystemRecentCPUAndMemoryMonitorEntry(
         searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves a list of all index monitor entries available in the Directory
   * Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all index monitor entries available in the Directory
   *          Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<IndexMonitorEntry> getIndexMonitorEntries(
                                             final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getIndexMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves a list of all index monitor entries available in the Directory
   * Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all index monitor entries available in the Directory
   *          Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<IndexMonitorEntry> getIndexMonitorEntries(
                                             final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         IndexMonitorEntry.INDEX_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<IndexMonitorEntry> monitorEntries =
         new ArrayList<IndexMonitorEntry>(searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new IndexMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves a list of all indicator gauge monitor entries available in the
   * Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all indicator gauge monitor entries available in the
   *          Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<IndicatorGaugeMonitorEntry>
              getIndicatorGaugeMonitorEntries(final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         GaugeMonitorEntry.GAUGE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<IndicatorGaugeMonitorEntry> monitorEntries =
         new ArrayList<IndicatorGaugeMonitorEntry>(
              searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new IndicatorGaugeMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves a list of all JE environment monitor entries available in the
   * Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all JE environment monitor entries available in the
   *          Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<JEEnvironmentMonitorEntry>
                     getJEEnvironmentMonitorEntries(
                          final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getJEEnvironmentMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves a list of all JE environment monitor entries available in the
   * Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all JE environment monitor entries available in the
   *          Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<JEEnvironmentMonitorEntry>
                     getJEEnvironmentMonitorEntries(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         JEEnvironmentMonitorEntry.JE_ENVIRONMENT_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<JEEnvironmentMonitorEntry> monitorEntries =
         new ArrayList<JEEnvironmentMonitorEntry>(searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new JEEnvironmentMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves a list of all LDAP external server monitor entries available in
   * the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all LDAP external server monitor entries available in
   *          the Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<LDAPExternalServerMonitorEntry>
                     getLDAPExternalServerMonitorEntries(
                          final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getLDAPExternalServerMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves a list of all LDAP external server monitor entries available in
   * the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all LDAP external server monitor entries available in
   *          the Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<LDAPExternalServerMonitorEntry>
                     getLDAPExternalServerMonitorEntries(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         LDAPExternalServerMonitorEntry.LDAP_EXTERNAL_SERVER_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<LDAPExternalServerMonitorEntry> monitorEntries =
         new ArrayList<LDAPExternalServerMonitorEntry>(
                  searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new LDAPExternalServerMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves a list of all LDAP statistics monitor entries available in the
   * Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all LDAP statistics monitor entries available in the
   *          Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<LDAPStatisticsMonitorEntry>
                     getLDAPStatisticsMonitorEntries(
                          final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getLDAPStatisticsMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves a list of all LDAP statistics monitor entries available in the
   * Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all LDAP statistics monitor entries available in the
   *          Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<LDAPStatisticsMonitorEntry>
                     getLDAPStatisticsMonitorEntries(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         LDAPStatisticsMonitorEntry.LDAP_STATISTICS_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<LDAPStatisticsMonitorEntry> monitorEntries =
         new ArrayList<LDAPStatisticsMonitorEntry>(
                  searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new LDAPStatisticsMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves a list of all load-balancing algorithm monitor entries available
   * in the Directory Proxy Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Proxy Server.
   *
   * @return  A list of all load-balancing algorithm monitor entries available
   *          in the Directory Proxy Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Proxy Server.
   */
  public static List<LoadBalancingAlgorithmMonitorEntry>
                     getLoadBalancingAlgorithmMonitorEntries(
                          final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getLoadBalancingAlgorithmMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves a list of all load-balancing algorithm monitor entries available
   * in the Directory Proxy Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Proxy Server.
   *
   * @return  A list of all load-balancing algorithm monitor entries available
   *          in the Directory Proxy Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Proxy Server.
   */
  public static List<LoadBalancingAlgorithmMonitorEntry>
                     getLoadBalancingAlgorithmMonitorEntries(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         LoadBalancingAlgorithmMonitorEntry.
              LOAD_BALANCING_ALGORITHM_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<LoadBalancingAlgorithmMonitorEntry> monitorEntries =
         new ArrayList<LoadBalancingAlgorithmMonitorEntry>(
                  searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new LoadBalancingAlgorithmMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves the memory usage monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The memory usage monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static MemoryUsageMonitorEntry getMemoryUsageMonitorEntry(
                                             final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getMemoryUsageMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the memory usage monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The memory usage monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static MemoryUsageMonitorEntry getMemoryUsageMonitorEntry(
                                             final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         MemoryUsageMonitorEntry.MEMORY_USAGE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getMemoryUsageMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getMemoryUsageMonitorEntry");
    }

    return new MemoryUsageMonitorEntry(searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves a list of all numeric gauge monitor entries available in the
   * Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all numeric gauge monitor entries available in the
   *          Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<NumericGaugeMonitorEntry>
              getNumericGaugeMonitorEntries(final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         GaugeMonitorEntry.GAUGE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<NumericGaugeMonitorEntry> monitorEntries =
         new ArrayList<NumericGaugeMonitorEntry>(
              searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new NumericGaugeMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves the per application processing time histogram monitor entries
   * from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The per application processing time histogram monitor entries from
   *          the Directory Server.  If none are available, an empty list is
   *          returned.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<PerApplicationProcessingTimeHistogramMonitorEntry>
                     getPerApplicationProcessingTimeHistogramMonitorEntries(
                          final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getPerApplicationProcessingTimeHistogramMonitorEntries(
         (LDAPInterface) connection);
  }



  /**
   * Retrieves the per application processing time histogram monitor entries
   * from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The per application processing time histogram monitor entries from
   *          the Directory Server.  If none are available, an empty list is
   *          returned.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<PerApplicationProcessingTimeHistogramMonitorEntry>
                     getPerApplicationProcessingTimeHistogramMonitorEntries(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         PerApplicationProcessingTimeHistogramMonitorEntry.
              PER_APPLICATION_PROCESSING_TIME_HISTOGRAM_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in " +
                 "getPerApplicationProcessingTimeHistogramMonitorEntries");

      return Collections.emptyList();
    }

    final List<PerApplicationProcessingTimeHistogramMonitorEntry> entries =
         new ArrayList<PerApplicationProcessingTimeHistogramMonitorEntry>();

    for (final Entry entry: searchResult.getSearchEntries())
    {
      entries.add(new PerApplicationProcessingTimeHistogramMonitorEntry(entry));
    }

    return entries;
  }



  /**
   * Retrieves the processing time histogram monitor entry from the Directory
   * Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The processing time histogram monitor entry from the Directory
   *          Server, or {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static ProcessingTimeHistogramMonitorEntry
                     getProcessingTimeHistogramMonitorEntry(
                          final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getProcessingTimeHistogramMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the processing time histogram monitor entry from the Directory
   * Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The processing time histogram monitor entry from the Directory
   *          Server, or {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static ProcessingTimeHistogramMonitorEntry
                     getProcessingTimeHistogramMonitorEntry(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         ProcessingTimeHistogramMonitorEntry.
                              PROCESSING_TIME_HISTOGRAM_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getProcessingTimeHistogramMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in " +
            "getProcessingTimeHistogramMonitorEntry");
    }

    return new ProcessingTimeHistogramMonitorEntry(
                    searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves a list of all replica monitor entries available in the Directory
   * Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all replica monitor entries available in the Directory
   *          Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<ReplicaMonitorEntry> getReplicaMonitorEntries(
                                               final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getReplicaMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves a list of all replica monitor entries available in the Directory
   * Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all replica monitor entries available in the Directory
   *          Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<ReplicaMonitorEntry> getReplicaMonitorEntries(
                                               final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         ReplicaMonitorEntry.REPLICA_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<ReplicaMonitorEntry> monitorEntries =
         new ArrayList<ReplicaMonitorEntry>(
                  searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new ReplicaMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves the replication server monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The replication server monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static ReplicationServerMonitorEntry getReplicationServerMonitorEntry(
                     final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getReplicationServerMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the replication server monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The replication server monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static ReplicationServerMonitorEntry getReplicationServerMonitorEntry(
                     final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         ReplicationServerMonitorEntry.REPLICATION_SERVER_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getReplicationServerMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in " +
            "getReplicationServerMonitorEntry");
    }

    return new ReplicationServerMonitorEntry(
                    searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves a list of all replication summary monitor entries available in
   * the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all replication summary monitor entries available in the
   *          Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<ReplicationSummaryMonitorEntry>
                     getReplicationSummaryMonitorEntries(
                          final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getReplicationSummaryMonitorEntries((LDAPInterface) connection);
  }



  /**
   * Retrieves a list of all replication summary monitor entries available in
   * the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  A list of all replication summary monitor entries available in the
   *          Directory Server.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static List<ReplicationSummaryMonitorEntry>
                     getReplicationSummaryMonitorEntries(
                          final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         ReplicationSummaryMonitorEntry.REPLICATION_SUMMARY_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final ArrayList<ReplicationSummaryMonitorEntry> monitorEntries =
         new ArrayList<ReplicationSummaryMonitorEntry>(
                  searchResult.getEntryCount());
    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      monitorEntries.add(new ReplicationSummaryMonitorEntry(e));
    }

    return Collections.unmodifiableList(monitorEntries);
  }



  /**
   * Retrieves the result code monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The result code monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static ResultCodeMonitorEntry getResultCodeMonitorEntry(
                                            final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         ResultCodeMonitorEntry.RESULT_CODE_MONITOR_OC);

    final SearchResult searchResult = connection.search(
         MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB, filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getResultCodeMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getResultCodeMonitorEntry");
    }

    return new ResultCodeMonitorEntry(searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves the system info monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The system info monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static SystemInfoMonitorEntry getSystemInfoMonitorEntry(
                                            final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getSystemInfoMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the system info monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The system info monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static SystemInfoMonitorEntry getSystemInfoMonitorEntry(
                                            final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         SystemInfoMonitorEntry.SYSTEM_INFO_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getSystemInfoMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getSystemInfoMonitorEntry");
    }

    return new SystemInfoMonitorEntry(searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves the stack trace monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The stack trace monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static StackTraceMonitorEntry getStackTraceMonitorEntry(
                                            final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getStackTraceMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the stack trace monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The stack trace monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static StackTraceMonitorEntry getStackTraceMonitorEntry(
                                            final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
                         StackTraceMonitorEntry.STACK_TRACE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getStackTraceMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getStackTraceMonitorEntry");
    }

    return new StackTraceMonitorEntry(searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves the traditional work queue monitor entry from the Directory
   * Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The traditional work queue monitor entry from the Directory
   *          Server, or {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static TraditionalWorkQueueMonitorEntry
         getTraditionalWorkQueueMonitorEntry(final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getTraditionalWorkQueueMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the traditional work queue monitor entry from the Directory
   * Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The traditional work queue monitor entry from the Directory
   *          Server, or {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static TraditionalWorkQueueMonitorEntry
         getTraditionalWorkQueueMonitorEntry(final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         TraditionalWorkQueueMonitorEntry.TRADITIONAL_WORK_QUEUE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getTraditionalWorkQueueMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getTraditionalWorkQueueMonitorEntry");
    }

    return new TraditionalWorkQueueMonitorEntry(
                    searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves the UnboundID work queue monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The UnboundID work queue monitor entry from the Directory Server,
   *          or {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static UnboundIDWorkQueueMonitorEntry
         getUnboundIDWorkQueueMonitorEntry(final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getUnboundIDWorkQueueMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the UnboundID work queue monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The UnboundID work queue monitor entry from the Directory Server,
   *          or {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static UnboundIDWorkQueueMonitorEntry
         getUnboundIDWorkQueueMonitorEntry(final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         UnboundIDWorkQueueMonitorEntry.UNBOUNDID_WORK_QUEUE_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getUnboundIDWorkQueueMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getUnboundIDWorkQueueMonitorEntry");
    }

    return new UnboundIDWorkQueueMonitorEntry(
                    searchResult.getSearchEntries().get(0));
  }



  /**
   * Retrieves the version monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The version monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static VersionMonitorEntry getVersionMonitorEntry(
                                         final LDAPConnection connection)
         throws LDAPSearchException
  {
    return getVersionMonitorEntry((LDAPInterface) connection);
  }



  /**
   * Retrieves the version monitor entry from the Directory Server.
   *
   * @param  connection  The connection to use to communicate with the Directory
   *                     Server.
   *
   * @return  The version monitor entry from the Directory Server, or
   *          {@code null} if it is not available.
   *
   * @throws  LDAPSearchException  If a problem occurs while communicating with
   *                               the Directory Server.
   */
  public static VersionMonitorEntry getVersionMonitorEntry(
                                         final LDAPInterface connection)
         throws LDAPSearchException
  {
    final Filter filter = Filter.createEqualityFilter("objectClass",
         VersionMonitorEntry.VERSION_MONITOR_OC);

    final SearchResult searchResult =
         connection.search(MonitorEntry.MONITOR_BASE_DN, SearchScope.SUB,
                           filter);

    final int numEntries = searchResult.getEntryCount();
    if (numEntries == 0)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "No entries returned in getVersionMonitorEntry");

      return null;
    }
    else if (numEntries != 1)
    {
      debug(Level.FINE, DebugType.MONITOR,
            "Multiple entries returned in getVersionMonitorEntry");
    }

    return new VersionMonitorEntry(searchResult.getSearchEntries().get(0));
  }
}
