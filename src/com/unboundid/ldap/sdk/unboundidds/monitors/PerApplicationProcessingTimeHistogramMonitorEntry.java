/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the
 * processing times of operations that are performed in the server in the
 * context of a single application.  It derives most of its functionality
 * from its parent class, {@link ProcessingTimeHistogramMonitorEntry}.  The
 * only additional information that is provided is the name of the application
 * to which the monitor entry applies.
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
 * The server can present zero or more per application processing time
 * histogram monitor entries.  They can be retrieved using the
 * {@link MonitorManager#getPerApplicationProcessingTimeHistogramMonitorEntries}
 * method.  This entry provides specific methods for accessing information about
 * processing times per bucket (e.g., the
 * Alternately, this information may be accessed using the generic
 * API.  See the {@link MonitorManager} class documentation for an example that
 * demonstrates the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level= ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PerApplicationProcessingTimeHistogramMonitorEntry
       extends ProcessingTimeHistogramMonitorEntry
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1467986373260986009L;



  /**
   * The structural object class used in processing time histogram monitor
   * entries.
   */
  @NotNull static final String
       PER_APPLICATION_PROCESSING_TIME_HISTOGRAM_MONITOR_OC =
            "ds-per-application-processing-time-histogram-monitor-entry";



  /**
   * The name of the attribute that contains the name of the application to
   * which this monitor entry applies.
   */
  @NotNull private static final String ATTR_APPLICATION_NAME =
       "applicationName";



  // The name of the application to which this monitor entry applies.
  @Nullable private final String applicationName;


  /**
   * Creates a new processing time histogram monitor entry from the provided
   * entry.
   *
   * @param  entry  The entry to be parsed as a processing time histogram
   *                monitor entry.  It must not be {@code null}.
   */
  public PerApplicationProcessingTimeHistogramMonitorEntry(
              @NotNull final Entry entry)
  {
    super(entry);

    applicationName = entry.getAttributeValue(ATTR_APPLICATION_NAME);
  }



  /**
   * Returns the name of the application to which this monitor entry applies.
   *
   * @return  The name of the application to which this monitor entry applies,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getApplicationName()
  {
    return applicationName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_PER_APP_PROCESSING_TIME_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_PER_APP_PROCESSING_TIME_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final Map<String,MonitorAttribute> superAttrs =
         super.getMonitorAttributes();

    final LinkedHashMap<String,MonitorAttribute> attrs = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(superAttrs.size()+1));
    attrs.putAll(superAttrs);

    if (applicationName != null)
    {
      addMonitorAttribute(attrs,
           ATTR_APPLICATION_NAME,
           INFO_PER_APP_PROCESSING_TIME_DISPNAME_APP_NAME.get(),
           INFO_PER_APP_PROCESSING_TIME_DESC_APP_NAME.get(),
           applicationName);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
