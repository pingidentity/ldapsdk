/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
 * This class defines a monitor entry that provides information about the recent
 * CPU and memory utilization of the underlying system.
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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class HostSystemRecentCPUAndMemoryMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in host system recent CPU and memory
   * monitor entries.
   */
  @NotNull static final String HOST_SYSTEM_RECENT_CPU_AND_MEMORY_MONITOR_OC =
       "ds-host-system-cpu-memory-monitor-entry";



  /**
   * The name of the attribute that contains the recent CPU idle percentage.
   */
  @NotNull private static final String ATTR_RECENT_CPU_IDLE = "recent-cpu-idle";



  /**
   * The name of the attribute that contains the recent CPU I/O wait percentage.
   */
  @NotNull private static final String ATTR_RECENT_CPU_IOWAIT =
       "recent-cpu-iowait";



  /**
   * The name of the attribute that contains the recent CPU system percentage.
   */
  @NotNull private static final String ATTR_RECENT_CPU_SYSTEM =
       "recent-cpu-system";



  /**
   * The name of the attribute that contains the recent CPU total busy
   * percentage.
   */
  @NotNull private static final String ATTR_RECENT_TOTAL_CPU_BUSY =
       "recent-cpu-used";



  /**
   * The name of the attribute that contains the recent CPU user percentage.
   */
  @NotNull private static final String ATTR_RECENT_CPU_USER = "recent-cpu-user";



  /**
   * The name of the attribute that contains the recent amount of free system
   * memory, in gigabytes.
   */
  @NotNull private static final String ATTR_RECENT_MEMORY_FREE_GB =
       "recent-memory-free-gb";



  /**
   * The name of the attribute that contains the recent percent of system memory
   * that is currently free.
   */
  @NotNull private static final String ATTR_RECENT_MEMORY_FREE_PCT =
       "recent-memory-pct-free";



  /**
   * The name of the attribute that contains the time the information was
   * last updated.
   */
  @NotNull private static final String ATTR_TIMESTAMP = "timestamp";



  /**
   * The name of the attribute that contains the total amount of system memory,
   * in gigabytes.
   */
  @NotNull private static final String ATTR_TOTAL_MEMORY_GB = "total-memory-gb";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4408434740529394905L;



  // The time the CPU and memory usage information was last updated.
  @Nullable private final Date timestamp;

  // The recent CPU idle percent.
  @Nullable private final Double recentCPUIdle;

  // The recent CPU I/O wait percent.
  @Nullable private final Double recentCPUIOWait;

  // The recent CPU system percent.
  @Nullable private final Double recentCPUSystem;

  // The recent CPU total percent busy.
  @Nullable private final Double recentCPUTotalBusy;

  // The recent CPU user percent.
  @Nullable private final Double recentCPUUser;

  // The recent free memory, in gigabytes.
  @Nullable private final Double recentMemoryFreeGB;

  // The recent free memory percent.
  @Nullable private final Double recentMemoryPercentFree;

  // The total amount of system memory, in gigabytes.
  @Nullable private final Double totalMemoryGB;



  /**
   * Creates a new host system recent CPU and memory monitor entry from the
   * provided entry.
   *
   * @param  entry  The entry to be parsed as a host system recent CPU and
   *                memory monitor entry.  It must not be {@code null}.
   */
  public HostSystemRecentCPUAndMemoryMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    timestamp = getDate(ATTR_TIMESTAMP);
    recentCPUIdle = getDouble(ATTR_RECENT_CPU_IDLE);
    recentCPUIOWait = getDouble(ATTR_RECENT_CPU_IOWAIT);
    recentCPUSystem = getDouble(ATTR_RECENT_CPU_SYSTEM);
    recentCPUUser = getDouble(ATTR_RECENT_CPU_USER);
    recentCPUTotalBusy = getDouble(ATTR_RECENT_TOTAL_CPU_BUSY);
    recentMemoryFreeGB = getDouble(ATTR_RECENT_MEMORY_FREE_GB);
    recentMemoryPercentFree = getDouble(ATTR_RECENT_MEMORY_FREE_PCT);
    totalMemoryGB = getDouble(ATTR_TOTAL_MEMORY_GB);
  }



  /**
   * Retrieves the time that the CPU and memory utilization data was last
   * updated, if available.
   *
   * @return  The time that the CPU and system memory utilization data was
   *          last updated, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Date getUpdateTime()
  {
    return timestamp;
  }



  /**
   * Retrieves the total percentage of recent CPU time spent in user, system, or
   * I/O wait states, if available.
   *
   * @return  The total percentage of recent CPU time spent in user, system, or
   *          I/O wait states, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Double getRecentCPUTotalBusyPercent()
  {
    return recentCPUTotalBusy;
  }



  /**
   * Retrieves the percentage of recent CPU time spent in the user state, if
   * available.
   *
   * @return  The percentage of recent CPU time spent in the user state, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Double getRecentCPUUserPercent()
  {
    return recentCPUUser;
  }



  /**
   * Retrieves the percentage of recent CPU time spent in the system state, if
   * available.
   *
   * @return  The percentage of recent CPU time spent in the system state, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Double getRecentCPUSystemPercent()
  {
    return recentCPUSystem;
  }



  /**
   * Retrieves the percentage of recent CPU time spent in the I/O wait state, if
   * available.
   *
   * @return  The percentage of recent CPU time spent in the I/O wait state, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Double getRecentCPUIOWaitPercent()
  {
    return recentCPUIOWait;
  }



  /**
   * Retrieves the percentage of recent CPU idle time, if available.
   *
   * @return  The percentage of recent CPU idle time, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public Double getRecentCPUIdlePercent()
  {
    return recentCPUIdle;
  }



  /**
   * Retrieves the total amount of system memory in gigabytes, if available.
   *
   * @return  The total amount of system memory in gigabytes, or {@code null} if
   *          it was not included in the monitor entry.
   */
  @Nullable()
  public Double getTotalSystemMemoryGB()
  {
    return totalMemoryGB;
  }



  /**
   * Retrieves the recent amount of free system memory in gigabytes, if
   * available.
   *
   * @return  The recent amount of free system memory in gigabytes, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Double getRecentSystemMemoryFreeGB()
  {
    return recentMemoryFreeGB;
  }



  /**
   * Retrieves the recent percentage of free system memory, if available.
   *
   * @return  The recent percentage of free system memory, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Double getRecentSystemMemoryPercentFree()
  {
    return recentMemoryPercentFree;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_CPU_MEM_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_CPU_MEM_MONITOR_DESC.get();
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

    if (timestamp != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TIMESTAMP,
           INFO_CPU_MEM_DISPNAME_TIMESTAMP.get(),
           INFO_CPU_MEM_DESC_TIMESTAMP.get(),
           timestamp);
    }

    if (recentCPUTotalBusy != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_TOTAL_CPU_BUSY,
           INFO_CPU_MEM_DISPNAME_RECENT_CPU_TOTAL_BUSY.get(),
           INFO_CPU_MEM_DESC_RECENT_CPU_TOTAL_BUSY.get(),
           recentCPUTotalBusy);
    }

    if (recentCPUUser != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_CPU_USER,
           INFO_CPU_MEM_DISPNAME_RECENT_CPU_USER.get(),
           INFO_CPU_MEM_DESC_RECENT_CPU_USER.get(),
           recentCPUUser);
    }

    if (recentCPUSystem != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_CPU_SYSTEM,
           INFO_CPU_MEM_DISPNAME_RECENT_CPU_SYSTEM.get(),
           INFO_CPU_MEM_DESC_RECENT_CPU_SYSTEM.get(),
           recentCPUSystem);
    }

    if (recentCPUIOWait != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_CPU_IOWAIT,
           INFO_CPU_MEM_DISPNAME_RECENT_CPU_IOWAIT.get(),
           INFO_CPU_MEM_DESC_RECENT_CPU_IOWAIT.get(),
           recentCPUIOWait);
    }

    if (recentCPUIdle != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_CPU_IDLE,
           INFO_CPU_MEM_DISPNAME_RECENT_CPU_IDLE.get(),
           INFO_CPU_MEM_DESC_RECENT_CPU_IDLE.get(),
           recentCPUIdle);
    }

    if (totalMemoryGB != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_MEMORY_GB,
           INFO_CPU_MEM_DISPNAME_TOTAL_MEM.get(),
           INFO_CPU_MEM_DESC_TOTAL_MEM.get(),
           totalMemoryGB);
    }

    if (recentMemoryFreeGB != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_MEMORY_FREE_GB,
           INFO_CPU_MEM_DISPNAME_FREE_MEM_GB.get(),
           INFO_CPU_MEM_DESC_FREE_MEM_GB.get(),
           recentMemoryFreeGB);
    }

    if (recentMemoryPercentFree != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_MEMORY_FREE_PCT,
           INFO_CPU_MEM_DISPNAME_FREE_MEM_PCT.get(),
           INFO_CPU_MEM_DESC_FREE_MEM_PCT.get(),
           recentMemoryPercentFree);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
