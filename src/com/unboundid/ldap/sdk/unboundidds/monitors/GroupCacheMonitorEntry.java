/*
 * Copyright 2014-2018 Ping Identity Corporation
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
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the group
 * cache and the number and types of groups available in the server.
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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GroupCacheMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in group cache monitor entries.
   */
  static final String GROUP_CACHE_MONITOR_OC =
       "ds-group-cache-monitor-entry";



  /**
   * The name of the attribute that contains information about the amount of
   * memory required by the group cache, in bytes.
   */
  private static final String ATTR_CURRENT_CACHE_USED_BYTES =
       "current-cache-used-bytes";



  /**
   * The name of the attribute that contains information about the amount of
   * memory required by the group cache, as a percentage of the total JVM heap
   * size.
   */
  private static final String ATTR_CURRENT_CACHE_USED_PERCENT =
       "current-cache-used-as-percentage-of-max-heap";



  /**
   * The name of the attribute that contains information about the length of
   * time required to determine group cache memory usage.
   */
  private static final String ATTR_CURRENT_CACHE_USED_UPDATE_MILLIS =
       "current-cache-used-update-ms";



  /**
   * The name of the attribute that contains information about the number of
   * dynamic group entries defined in the server.
   */
  private static final String ATTR_DYNAMIC_GROUP_ENTRIES =
       "dynamic-group-entries";



  /**
   * The name of the attribute that contains information about the number of
   * static group entries defined in the server.
   */
  private static final String ATTR_STATIC_GROUP_ENTRIES =
       "static-group-entries";



  /**
   * The name of the attribute that contains information about the total number
   * of static group members defined in the server.
   */
  private static final String ATTR_TOTAL_STATIC_GROUP_MEMBERS =
       "static-group-members";



  /**
   * The name of the attribute that contains information about the number of
   * unique static group members defined in the server.
   */
  private static final String ATTR_UNIQUE_STATIC_GROUP_MEMBERS =
       "static-group-unique-members";



  /**
   * The name of the attribute that contains information about the number of
   * virtual static group entries defined in the server.
   */
  private static final String ATTR_VIRTUAL_STATIC_GROUP_ENTRIES =
       "virtual-static-group-entries";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5665905374595185773L;



  // The length of time in milliseconds required to determine the current cache
  // usage.
  private final Double currentCacheUsedUpdateMillis;

  // The percentage of the JVM heap used by the group cache.
  private final Integer currentCacheUsedPercent;

  // The amount of memory (in bytes) currently in use by the group cache.
  private final Long currentCacheUsedBytes;

  // The number of dynamic group entries defined in the server.
  private final Long dynamicGroupEntries;

  // The number of static group entries defined in the server.
  private final Long staticGroupEntries;

  // The number of total static group members defined in the server.
  private final Long staticGroupMembers;

  // The number of unique static group members defined in the server.
  private final Long staticGroupUniqueMembers;

  // The number of virtual static group entries defined in the server.
  private final Long virtualStaticGroupEntries;



  /**
   * Creates a new group cache monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a group cache monitor entry.  It
   *                must not be {@code null}.
   */
  public GroupCacheMonitorEntry(final Entry entry)
  {
    super(entry);

    staticGroupEntries = getLong(ATTR_STATIC_GROUP_ENTRIES);
    staticGroupMembers = getLong(ATTR_TOTAL_STATIC_GROUP_MEMBERS);
    staticGroupUniqueMembers = getLong(ATTR_UNIQUE_STATIC_GROUP_MEMBERS);
    dynamicGroupEntries = getLong(ATTR_DYNAMIC_GROUP_ENTRIES);
    virtualStaticGroupEntries = getLong(ATTR_VIRTUAL_STATIC_GROUP_ENTRIES);
    currentCacheUsedBytes = getLong(ATTR_CURRENT_CACHE_USED_BYTES);
    currentCacheUsedPercent = getInteger(ATTR_CURRENT_CACHE_USED_PERCENT);
    currentCacheUsedUpdateMillis =
         getDouble(ATTR_CURRENT_CACHE_USED_UPDATE_MILLIS);
  }



  /**
   * Retrieves the number of static group entries defined in the server, if
   * available.
   *
   * @return  The number of static group entries defined in the server, or
   *          {@code null} if it was not included in the monitor entry.
   */
  public Long getStaticGroupEntries()
  {
    return staticGroupEntries;
  }



  /**
   * Retrieves the total number of static group members defined in the server,
   * if available.  Users that are members of multiple static groups will be
   * counted multiple times.
   *
   * @return  The total number of static group members defined in the server, or
   *          {@code null} if it was not included in the monitor entry.
   */
  public Long getTotalStaticGroupMembers()
  {
    return staticGroupMembers;
  }



  /**
   * Retrieves the number of unique static group members defined in the server,
   * if available.  Users that are members of multiple static groups will only
   * be counted once.
   *
   * @return  The number of unique static group members defined in the server,
   *          or {@code null} if it was not included in the monitor entry.
   */
  public Long getUniqueStaticGroupMembers()
  {
    return staticGroupUniqueMembers;
  }



  /**
   * Retrieves the number of dynamic group entries defined in the server, if
   * available.
   *
   * @return  The number of dynamic group entries defined in the server, or
   *          {@code null} if it was not included in the monitor entry.
   */
  public Long getDynamicGroupEntries()
  {
    return dynamicGroupEntries;
  }



  /**
   * Retrieves the number of virtual static group entries defined in the server,
   * if available.
   *
   * @return  The number of virtual static group entries defined in the server,
   *          or {@code null} if it was not included in the monitor entry.
   */
  public Long getVirtualStaticGroupEntries()
  {
    return virtualStaticGroupEntries;
  }



  /**
   * Retrieves the amount of memory in bytes used by the group cache, if
   * available.
   *
   * @return  The amount of memory in bytes used by the group cache, or
   *          {@code null} if it was not included in the monitor entry.
   */
  public Long getCurrentCacheUsedBytes()
  {
    return currentCacheUsedBytes;
  }



  /**
   * Retrieves the amount of memory used by the group cache as a percentage of
   * the maximum heap size, if available.
   *
   * @return  The amount of memory in bytes used by the group cache, or
   *          {@code null} if it was not included in the monitor entry.
   */
  public Integer getCurrentCacheUsedAsPercentOfMaxHeap()
  {
    return currentCacheUsedPercent;
  }



  /**
   * Retrieves the length of time in milliseconds required to compute the group
   * cache size, if available.
   *
   * @return  The length of time in milliseconds required to compute the group
   *          cache size, or {@code null} if it was not included in the monitor
   *          entry.
   */
  public Double getCurrentCacheUsedUpdateDurationMillis()
  {
    return currentCacheUsedUpdateMillis;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDisplayName()
  {
    return INFO_GROUP_CACHE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDescription()
  {
    return INFO_GROUP_CACHE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<String,MonitorAttribute>(8);

    if (staticGroupEntries != null)
    {
      addMonitorAttribute(attrs,
           ATTR_STATIC_GROUP_ENTRIES,
           INFO_GROUP_CACHE_DISPNAME_STATIC_GROUP_ENTRIES.get(),
           INFO_GROUP_CACHE_DESC_STATIC_GROUP_ENTRIES.get(),
           staticGroupEntries);
    }

    if (staticGroupMembers != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_STATIC_GROUP_MEMBERS,
           INFO_GROUP_CACHE_DISPNAME_STATIC_GROUP_MEMBERS.get(),
           INFO_GROUP_CACHE_DESC_STATIC_GROUP_MEMBERS.get(),
           staticGroupMembers);
    }

    if (staticGroupUniqueMembers != null)
    {
      addMonitorAttribute(attrs,
           ATTR_UNIQUE_STATIC_GROUP_MEMBERS,
           INFO_GROUP_CACHE_DISPNAME_STATIC_GROUP_UNIQUE_MEMBERS.get(),
           INFO_GROUP_CACHE_DESC_STATIC_GROUP_UNIQUE_MEMBERS.get(),
           staticGroupUniqueMembers);
    }

    if (dynamicGroupEntries != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DYNAMIC_GROUP_ENTRIES,
           INFO_GROUP_CACHE_DISPNAME_DYNAMIC_GROUP_ENTRIES.get(),
           INFO_GROUP_CACHE_DESC_DYNAMIC_GROUP_ENTRIES.get(),
           dynamicGroupEntries);
    }

    if (virtualStaticGroupEntries != null)
    {
      addMonitorAttribute(attrs,
           ATTR_VIRTUAL_STATIC_GROUP_ENTRIES,
           INFO_GROUP_CACHE_DISPNAME_VIRTUAL_STATIC_GROUP_ENTRIES.get(),
           INFO_GROUP_CACHE_DESC_VIRTUAL_STATIC_GROUP_ENTRIES.get(),
           virtualStaticGroupEntries);
    }

    if (currentCacheUsedBytes != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_CACHE_USED_BYTES,
           INFO_GROUP_CACHE_DISPNAME_CACHE_SIZE_BYTES.get(),
           INFO_GROUP_CACHE_DESC_CACHE_SIZE_BYTES.get(),
           currentCacheUsedBytes);
    }

    if (currentCacheUsedPercent != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_CACHE_USED_PERCENT,
           INFO_GROUP_CACHE_DISPNAME_CACHE_SIZE_PERCENT.get(),
           INFO_GROUP_CACHE_DESC_CACHE_SIZE_PERCENT.get(),
           currentCacheUsedPercent);
    }

    if (currentCacheUsedUpdateMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_CACHE_USED_UPDATE_MILLIS,
           INFO_GROUP_CACHE_DISPNAME_CACHE_SIZE_UPDATE_MILLIS.get(),
           INFO_GROUP_CACHE_DESC_CACHE_SIZE_UPDATE_MILLIS.get(),
           currentCacheUsedUpdateMillis);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
