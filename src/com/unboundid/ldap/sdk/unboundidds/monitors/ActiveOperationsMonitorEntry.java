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



import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the
 * operations currently being processed by the Directory Server.
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
 * The server should present at most one active operations monitor entry.  It
 * can be retrieved using the
 * {@link MonitorManager#getActiveOperationsMonitorEntry} method.  The
 * {@link ActiveOperationsMonitorEntry#getActiveOperations} method may be used
 * to retrieve information for each operation in progress.  Alternately, this
 * information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ActiveOperationsMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in active operations monitor entries.
   */
  static final String ACTIVE_OPERATIONS_MONITOR_OC =
       "ds-active-operations-monitor-entry";



  /**
   * The name of the attribute that contains information about the number of
   * operations currently in progress.
   */
  private static final String ATTR_NUM_OPS_IN_PROGRESS =
       "num-operations-in-progress";



  /**
   * The name of the attribute that contains information about the number of
   * persistent searches currently in progress.
   */
  private static final String ATTR_NUM_PSEARCHES_IN_PROGRESS =
       "num-persistent-searches-in-progress";



  /**
   * The name of the attribute that contains information about an operation in
   * progress.
   */
  private static final String ATTR_OP_IN_PROGRESS = "operation-in-progress";



  /**
   * The name of the attribute that contains information about a persistent
   * search in progress.
   */
  private static final String ATTR_PSEARCH_IN_PROGRESS =
       "persistent-search-in-progress";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6583987693176406802L;



  // The list of operations currently in progress.
  private final List<String> activeOperations;

  // The list of persistent searches currently in progress.
  private final List<String> activePersistentSearches;

  // The number of operations currently in progress.
  private final Long numOpsInProgress;

  // The number of persistent searches currently in progress.
  private final Long numPsearchesInProgress;



  /**
   * Creates a new active operations monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a active operations monitor entry.
   *                It must not be {@code null}.
   */
  public ActiveOperationsMonitorEntry(final Entry entry)
  {
    super(entry);

    activeOperations         = getStrings(ATTR_OP_IN_PROGRESS);
    activePersistentSearches = getStrings(ATTR_PSEARCH_IN_PROGRESS);
    numOpsInProgress         = getLong(ATTR_NUM_OPS_IN_PROGRESS);
    numPsearchesInProgress   = getLong(ATTR_NUM_PSEARCHES_IN_PROGRESS);
  }



  /**
   * Retrieves the number of operations currently in progress in the Directory
   * Server.
   *
   * @return  The number of operations currently in progress in the Directory
   *          Server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  public Long getNumOperationsInProgress()
  {
    return numOpsInProgress;
  }



  /**
   * Retrieves a list of the string representations of the operations in
   * progress in the Directory Server.
   *
   * @return  A list of the string representations of the operations in
   *          progress in the Directory Server, or an empty list if it was not
   *          included in the monitor entry.
   */
  public List<String> getActiveOperations()
  {
    return activeOperations;
  }



  /**
   * Retrieves the number of persistent searches currently in progress in the
   * Directory Server.
   *
   * @return  The number of persistent searches currently in progress in the
   *          Directory Server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  public Long getNumPersistentSearchesInProgress()
  {
    return numPsearchesInProgress;
  }



  /**
   * Retrieves a list of the string representations of the persistent searches
   * in progress in the Directory Server.
   *
   * @return  A list of the string representations of the persistent searches in
   *          progress in the Directory Server, or an empty list if it was not
   *          included in the monitor entry.
   */
  public List<String> getActivePersistentSearches()
  {
    return activePersistentSearches;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDisplayName()
  {
    return INFO_ACTIVE_OPERATIONS_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDescription()
  {
    return INFO_ACTIVE_OPERATIONS_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<String,MonitorAttribute>();

    if (numOpsInProgress != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_OPS_IN_PROGRESS,
           INFO_ACTIVE_OPERATIONS_DISPNAME_NUM_OPS_IN_PROGRESS.get(),
           INFO_ACTIVE_OPERATIONS_DESC_NUM_OPS_IN_PROGRESS.get(),
           numOpsInProgress);
    }

    if (! activeOperations.isEmpty())
    {
      addMonitorAttribute(attrs,
           ATTR_OP_IN_PROGRESS,
           INFO_ACTIVE_OPERATIONS_DISPNAME_OPS_IN_PROGRESS.get(),
           INFO_ACTIVE_OPERATIONS_DESC_OPS_IN_PROGRESS.get(),
           activeOperations);
    }

    if (numPsearchesInProgress != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_PSEARCHES_IN_PROGRESS,
           INFO_ACTIVE_OPERATIONS_DISPNAME_NUM_PSEARCHES_IN_PROGRESS.get(),
           INFO_ACTIVE_OPERATIONS_DESC_NUM_PSEARCHES_IN_PROGRESS.get(),
           numPsearchesInProgress);
    }

    if (! activePersistentSearches.isEmpty())
    {
      addMonitorAttribute(attrs,
           ATTR_PSEARCH_IN_PROGRESS,
           INFO_ACTIVE_OPERATIONS_DISPNAME_PSEARCHES_IN_PROGRESS.get(),
           INFO_ACTIVE_OPERATIONS_DESC_PSEARCHES_IN_PROGRESS.get(),
           activePersistentSearches);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
