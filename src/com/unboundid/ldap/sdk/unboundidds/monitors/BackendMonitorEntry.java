/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides general information about a
 * Directory Server backend.
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
 * Information that may be available in a backend monitor entry includes:
 * <UL>
 *   <LI>The backend ID for the backend.</LI>
 *   <LI>The set of base DNs for the backend.</LI>
 *   <LI>The total number of entries in the backend.</LI>
 *   <LI>The number of entries in the backend per base DN.</LI>
 *   <LI>The writability mode for the backend, which indicates whether it will
 *       accept write operations.</LI>
 *   <LI>An indication about whether the backend is public (intended to hold
 *       user data) or private (intended to hold operational data).</LI>
 * </UL>
 * The set of backend monitor entries published by the directory server can be
 * obtained using the {@link MonitorManager#getBackendMonitorEntries} method.
 * Specific methods are available for accessing the associated monitor data
 * (e.g., {@link BackendMonitorEntry#getBackendID} to retrieve the backend ID),
 * and there are also methods for accessing this information in a generic manner
 * (e.g., {@link BackendMonitorEntry#getMonitorAttributes} to retrieve all of
 * the monitor attributes).  See the {@link MonitorManager} class documentation
 * for an example that demonstrates the use of the generic API for accessing
 * monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BackendMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in backend monitor entries.
   */
  @NotNull static final String BACKEND_MONITOR_OC = "ds-backend-monitor-entry";



  /**
   * The name of the attribute that contains the backend ID.
   */
  @NotNull private static final String ATTR_BACKEND_ID = "ds-backend-id";



  /**
   * The name of the attribute that specifies the base DN(s) for the backend.
   */
  @NotNull private static final String ATTR_BASE_DN = "ds-backend-base-dn";



  /**
   * The name of the attribute that specifies the number of entries per base DN
   * in the backend.
   */
  @NotNull private static final String ATTR_ENTRIES_PER_BASE_DN =
       "ds-base-dn-entry-count";



  /**
   * The name of the attribute that indicates whether the backend is a private
   * backend.
   */
  @NotNull private static final String ATTR_IS_PRIVATE =
       "ds-backend-is-private";



  /**
   * The name of the attribute that holds the number of soft deletes processed
   * since the backend was initialized.
   */
  @NotNull private static final String ATTR_SOFT_DELETE_COUNT =
       "ds-soft-delete-operations-count";



  /**
   * The name of the attribute that specifies the total number of entries in the
   * backend.
   */
  @NotNull private static final String ATTR_TOTAL_ENTRIES =
       "ds-backend-entry-count";



  /**
   * The name of the attribute that holds the number of undeletes processed
   * since the backend was initialized.
   */
  @NotNull private static final String ATTR_UNDELETE_COUNT =
       "ds-undelete-operations-count";



  /**
   * The name of the attribute that specifies the writability mode for the
   * backend.
   */
  @NotNull  private static final String ATTR_WRITABILITY_MODE =
       "ds-backend-writability-mode";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4256944695436807547L;



  // Indicates whether the backend is a private backend.
  @Nullable private final Boolean isPrivate;

  // The base DNs for the backend.
  @NotNull private final List<String> baseDNs;

  // The number of soft delete operations processed since the backend was
  // started.
  @Nullable private final Long softDeleteCount;

  // The total number of entries in the backend.
  @Nullable private final Long totalEntries;

  // The number of undelete operations processed since the backend was started.
  @Nullable private final Long undeleteCount;

  // The number of entries per base DN in the backend.
  @NotNull private final Map<String,Long> entriesPerBaseDN;

  // The backend ID for the backend.
  @Nullable private final String backendID;

  // The writability mode for the backend.
  @Nullable private final String writabilityMode;



  /**
   * Creates a new backend monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a backend monitor entry.  It must
   *                not be {@code null}.
   */
  public BackendMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    backendID       = getString(ATTR_BACKEND_ID);
    baseDNs         = getStrings(ATTR_BASE_DN);
    isPrivate       = getBoolean(ATTR_IS_PRIVATE);
    softDeleteCount = getLong(ATTR_SOFT_DELETE_COUNT);
    totalEntries    = getLong(ATTR_TOTAL_ENTRIES);
    undeleteCount   = getLong(ATTR_UNDELETE_COUNT);
    writabilityMode = getString(ATTR_WRITABILITY_MODE);

    final List<String> entriesPerBase = getStrings(ATTR_ENTRIES_PER_BASE_DN);
    final LinkedHashMap<String,Long> countMap = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(entriesPerBase.size()));
    for (final String s : entriesPerBase)
    {
      try
      {
        final int spacePos = s.indexOf(' ');
        final Long l = Long.parseLong(s.substring(0, spacePos));
        final String dn = s.substring(spacePos+1).trim();
        countMap.put(dn, l);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (Debug.debugEnabled(DebugType.MONITOR))
        {
          Debug.debugMonitor(entry,
               "Cannot parse value '" + s + "' for attribute " +
                    ATTR_ENTRIES_PER_BASE_DN);
        }
      }
    }

    entriesPerBaseDN = Collections.unmodifiableMap(countMap);
  }



  /**
   * Retrieves the backend ID for the associated backend.
   *
   * @return  The backend ID for the associated backend, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public String getBackendID()
  {
    return backendID;
  }



  /**
   * Retrieves the base DNs for the associated backend.
   *
   * @return  The base DNs for the associated backend, or an empty list if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public List<String> getBaseDNs()
  {
    return baseDNs;
  }



  /**
   * Indicates whether the associated backend is a private backend.
   *
   * @return  {@code Boolean.TRUE} if the backend is a private backend,
   *          {@code Boolean.FALSE} if it is not a private backend, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Boolean isPrivate()
  {
    return isPrivate;
  }



  /**
   * Retrieves the writability mode for the associated backend.
   *
   * @return  The writability mode for the associated backend, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public String getWritabilityMode()
  {
    return writabilityMode;
  }



  /**
   * Retrieves the total number of entries in the associated backend.
   *
   * @return  The total number of entries in the associated backend, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getTotalEntries()
  {
    return totalEntries;
  }



  /**
   * Retrieves a count of the number of entries per base DN in the associated
   * backend.
   *
   * @return  A count of the number of entries per base DN in the associated
   *          backend, or an empty map if it was not included in the monitor
   *          entry.
   */
  @NotNull()
  public Map<String,Long> getEntriesPerBaseDN()
  {
    return entriesPerBaseDN;
  }



  /**
   * Retrieves the number of soft delete operations processed in the backend
   * since the backend was started.
   *
   * @return  The number of soft delete operations processed in the backend
   *          since the backend was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Long getSoftDeleteCount()
  {
    return softDeleteCount;
  }



  /**
   * Retrieves the number of undelete operations processed in the backend since
   * the backend was started.
   *
   * @return  The number of undelete operations processed in the backend since
   *          the backend was started, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public Long getUndeleteCount()
  {
    return undeleteCount;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_BACKEND_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_BACKEND_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));

    if (backendID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BACKEND_ID,
           INFO_BACKEND_DISPNAME_BACKEND_ID.get(),
           INFO_BACKEND_DESC_BACKEND_ID.get(),
           backendID);
    }

    if (! baseDNs.isEmpty())
    {
      addMonitorAttribute(attrs,
           ATTR_BASE_DN,
           INFO_BACKEND_DISPNAME_BASE_DN.get(),
           INFO_BACKEND_DESC_BASE_DN.get(),
           baseDNs);
    }

    if (totalEntries != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_ENTRIES,
           INFO_BACKEND_DISPNAME_TOTAL_ENTRIES.get(),
           INFO_BACKEND_DESC_TOTAL_ENTRIES.get(),
           totalEntries);
    }

    for (final String baseDN : entriesPerBaseDN.keySet())
    {
      final Long count = entriesPerBaseDN.get(baseDN);
      addMonitorAttribute(attrs,
                          ATTR_ENTRIES_PER_BASE_DN + '-' + baseDN,
                          INFO_BACKEND_DISPNAME_ENTRY_COUNT.get(baseDN),
                          INFO_BACKEND_DESC_ENTRY_COUNT.get(baseDN),
                          count);

    }

    if (softDeleteCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SOFT_DELETE_COUNT,
           INFO_BACKEND_DISPNAME_SOFT_DELETE_COUNT.get(),
           INFO_BACKEND_DESC_SOFT_DELETE_COUNT.get(),
           softDeleteCount);
    }

    if (undeleteCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_UNDELETE_COUNT,
           INFO_BACKEND_DISPNAME_UNDELETE_COUNT.get(),
           INFO_BACKEND_DESC_UNDELETE_COUNT.get(),
           undeleteCount);
    }

    if (writabilityMode != null)
    {
      addMonitorAttribute(attrs,
           ATTR_WRITABILITY_MODE,
           INFO_BACKEND_DISPNAME_WRITABILITY_MODE.get(),
           INFO_BACKEND_DESC_WRITABILITY_MODE.get(),
           writabilityMode);
    }

    if (isPrivate != null)
    {
      addMonitorAttribute(attrs,
           ATTR_IS_PRIVATE,
           INFO_BACKEND_DISPNAME_IS_PRIVATE.get(),
           INFO_BACKEND_DESC_IS_PRIVATE.get(),
           isPrivate);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
