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



import java.util.ArrayList;
import java.util.Collections;
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
 * This class defines a monitor entry that provides information about the disk
 * space usage of the Directory Server.
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
 * The server should present at most one disk space usage monitor entry.  It
 * can be retrieved using the
 * {@link MonitorManager#getDiskSpaceUsageMonitorEntry} method.  The
 * {@link DiskSpaceUsageMonitorEntry#getDiskSpaceInfo} method may be used
 * to retrieve information about the components which may consume significant
 * amounts of disk space, and the
 * {@link DiskSpaceUsageMonitorEntry#getCurrentState} method may be used to
 * obtain the current state of the server.  Alternately, this information may be
 * accessed using the generic API.  See the {@link MonitorManager} class
 * documentation for an example that demonstrates the use of the generic API for
 * accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DiskSpaceUsageMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in disk space usage monitor entries.
   */
  @NotNull static final String DISK_SPACE_USAGE_MONITOR_OC =
       "ds-disk-space-usage-monitor-entry";



  /**
   * The name of the attribute that contains information about the current disk
   * space state for the server.
   */
  @NotNull private static final String ATTR_CURRENT_STATE =
       "current-disk-space-state";



  /**
   * The prefix used for attributes that provide information about the name of
   * a disk space consumer.
   */
  @NotNull private static final String ATTR_PREFIX_CONSUMER_NAME =
       "disk-space-consumer-name-";



  /**
   * The prefix used for attributes that provide information about the path of
   * a disk space consumer.
   */
  @NotNull private static final String ATTR_PREFIX_CONSUMER_PATH =
       "disk-space-consumer-path-";



  /**
   * The prefix used for attributes that provide information about total bytes
   * for a disk space consumer.
   */
  @NotNull private static final String ATTR_PREFIX_CONSUMER_TOTAL_BYTES =
       "disk-space-consumer-total-bytes-";



  /**
   * The prefix used for attributes that provide information about usable bytes
   * for a disk space consumer.
   */
  @NotNull private static final String ATTR_PREFIX_CONSUMER_USABLE_BYTES =
       "disk-space-consumer-usable-bytes-";



  /**
   * The prefix used for attributes that provide information about usable
   * percent for a disk space consumer.
   */
  @NotNull private static final String ATTR_PREFIX_CONSUMER_USABLE_PERCENT =
       "disk-space-consumer-usable-percent-";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4717940564786806566L;



  // The list of disk space info objects parsed from this monitor entry.
  @NotNull private final List<DiskSpaceInfo> diskSpaceInfo;

  // The current disk space usage state for the server.
  @Nullable private final String currentState;



  /**
   * Creates a new disk space usage monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a disk space usage monitor entry.
   *                It must not be {@code null}.
   */
  public DiskSpaceUsageMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    currentState = getString(ATTR_CURRENT_STATE);

    int i=1;
    final ArrayList<DiskSpaceInfo> list = new ArrayList<>(5);
    while (true)
    {
      final String name = getString(ATTR_PREFIX_CONSUMER_NAME + i);
      if (name == null)
      {
        break;
      }

      final String path = getString(ATTR_PREFIX_CONSUMER_PATH + i);
      final Long totalBytes = getLong(ATTR_PREFIX_CONSUMER_TOTAL_BYTES + i);
      final Long usableBytes = getLong(ATTR_PREFIX_CONSUMER_USABLE_BYTES + i);
      final Long usablePercent =
           getLong(ATTR_PREFIX_CONSUMER_USABLE_PERCENT + i);

      list.add(new DiskSpaceInfo(name, path, totalBytes, usableBytes,
                                 usablePercent));

      i++;
    }

    diskSpaceInfo = Collections.unmodifiableList(list);
  }



  /**
   * Retrieves the current disk space state for the Directory Server.  It may
   * be one of "normal", "low space warning", "low space error", or "out of
   * space error".
   *
   * @return  The current disk space state for the Directory Server, or
   *          {@code null} if that information is not available.
   */
  @Nullable()
  public String getCurrentState()
  {
    return currentState;
  }



  /**
   * Retrieves a list of information about the disk space consumers defined in
   * the Directory Server.
   *
   * @return  A list of information about the disk space consumers defined in
   *          the Directory Server.
   */
  @NotNull()
  public List<DiskSpaceInfo> getDiskSpaceInfo()
  {
    return diskSpaceInfo;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_DISK_SPACE_USAGE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_DISK_SPACE_USAGE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));

    if (currentState != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_STATE,
           INFO_DISK_SPACE_USAGE_DISPNAME_CURRENT_STATE.get(),
           INFO_DISK_SPACE_USAGE_DESC_CURRENT_STATE.get(),
           currentState);
    }

    if (! diskSpaceInfo.isEmpty())
    {
      int i=1;
      for (final DiskSpaceInfo info : diskSpaceInfo)
      {
        if (info.getConsumerName() != null)
        {
          addMonitorAttribute(attrs,
               ATTR_PREFIX_CONSUMER_NAME + i,
               INFO_DISK_SPACE_USAGE_DISPNAME_DISK_SPACE_CONSUMER_PREFIX.get() +
                    ' ' + i + ' ' +
                    INFO_DISK_SPACE_USAGE_DISPNAME_NAME_SUFFIX.get(),
               INFO_DISK_SPACE_USAGE_DESC_NAME.get(),
               info.getConsumerName());
        }

        if (info.getPath() != null)
        {
          addMonitorAttribute(attrs,
               ATTR_PREFIX_CONSUMER_PATH + i,
               INFO_DISK_SPACE_USAGE_DISPNAME_DISK_SPACE_CONSUMER_PREFIX.get() +
                    ' ' + i + ' ' +
                    INFO_DISK_SPACE_USAGE_DISPNAME_PATH_SUFFIX.get(),
               INFO_DISK_SPACE_USAGE_DESC_PATH.get(),
               info.getPath());
        }

        if (info.getTotalBytes() != null)
        {
          addMonitorAttribute(attrs,
               ATTR_PREFIX_CONSUMER_TOTAL_BYTES + i,
               INFO_DISK_SPACE_USAGE_DISPNAME_DISK_SPACE_CONSUMER_PREFIX.get() +
                    ' ' + i + ' ' +
                    INFO_DISK_SPACE_USAGE_DISPNAME_TOTAL_BYTES_SUFFIX.get(),
               INFO_DISK_SPACE_USAGE_DESC_TOTAL_BYTES.get(),
               info.getTotalBytes());
        }

        if (info.getUsableBytes() != null)
        {
          addMonitorAttribute(attrs,
               ATTR_PREFIX_CONSUMER_USABLE_BYTES + i,
               INFO_DISK_SPACE_USAGE_DISPNAME_DISK_SPACE_CONSUMER_PREFIX.get() +
                    ' ' + i + ' ' +
                    INFO_DISK_SPACE_USAGE_DISPNAME_USABLE_BYTES_SUFFIX.get(),
               INFO_DISK_SPACE_USAGE_DESC_USABLE_BYTES.get(),
               info.getUsableBytes());
        }

        if (info.getUsablePercent() != null)
        {
          addMonitorAttribute(attrs,
               ATTR_PREFIX_CONSUMER_USABLE_PERCENT + i,
               INFO_DISK_SPACE_USAGE_DISPNAME_DISK_SPACE_CONSUMER_PREFIX.get() +
                    ' ' + i + ' ' +
                    INFO_DISK_SPACE_USAGE_DISPNAME_USABLE_PERCENT_SUFFIX.get(),
               INFO_DISK_SPACE_USAGE_DESC_USABLE_PERCENT.get(),
               info.getUsablePercent());
        }

        i++;
      }
    }

    return Collections.unmodifiableMap(attrs);
  }
}
