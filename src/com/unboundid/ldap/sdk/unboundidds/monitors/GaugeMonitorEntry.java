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
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.unboundidds.AlarmSeverity;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines the base class for gauge monitor entries, which provide
 * information common to all types of gauges.  Subclasses may provide more
 * specific information for that specific type of gauge.
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
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class GaugeMonitorEntry
       extends MonitorEntry
{
  /**
   * The base structural object class used in gauge monitor entries.
   */
  @NotNull static final String GAUGE_MONITOR_OC = "ds-gauge-monitor-entry";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long   serialVersionUID = -6092840651638645538L;



  // The current severity for the gauge.
  @Nullable private final AlarmSeverity currentSeverity;

  // The previous severity for the gauge.
  @Nullable private final AlarmSeverity previousSeverity;

  // The time the gauge entered the current severity.
  @Nullable private final Date currentSeverityStartTime;

  // The time the gauge last exited the critical state.
  @Nullable private final Date lastCriticalStateEndTime;

  // The time the gauge last entered the critical state.
  @Nullable private final Date lastCriticalStateStartTime;

  // The time the gauge last exited the major state.
  @Nullable private final Date lastMajorStateEndTime;

  // The time the gauge last entered the major state.
  @Nullable private final Date lastMajorStateStartTime;

  // The time the gauge last exited the minor state.
  @Nullable private final Date lastMinorStateEndTime;

  // The time the gauge last entered the minor state.
  @Nullable private final Date lastMinorStateStartTime;

  // The time the gauge last exited the normal state.
  @Nullable private final Date lastNormalStateEndTime;

  // The time the gauge last entered the normal state.
  @Nullable private final Date lastNormalStateStartTime;

  // The time the gauge last exited the warning state.
  @Nullable private final Date lastWarningStateEndTime;

  // The time the gauge last entered the normal state.
  @Nullable private final Date lastWarningStateStartTime;

  // The time the gauge information was initialized.
  @Nullable private final Date initTime;

  // The time the gauge information was last updated.
  @Nullable private final Date updateTime;

  // The error messages.
  @NotNull private final List<String> errorMessages;

  // The current severity duration in milliseconds.
  @Nullable private final Long currentSeverityDurationMillis;

  // The last critical state duration in milliseconds.
  @Nullable private final Long lastCriticalStateDurationMillis;

  // The last major state duration in milliseconds.
  @Nullable private final Long lastMajorStateDurationMillis;

  // The last minor state duration in milliseconds.
  @Nullable private final Long lastMinorStateDurationMillis;

  // The last normal state duration in milliseconds.
  @Nullable private final Long lastNormalStateDurationMillis;

  // The last warning state duration in milliseconds.
  @Nullable private final Long lastWarningStateDurationMillis;

  // The number of samples taken in the current interval.
  @Nullable private final Long samplesThisInterval;

  // The total critical state duration in milliseconds.
  @Nullable private final Long totalCriticalStateDurationMillis;

  // The total major state duration in milliseconds.
  @Nullable private final Long totalMajorStateDurationMillis;

  // The total minor state duration in milliseconds.
  @Nullable private final Long totalMinorStateDurationMillis;

  // The total normal state duration in milliseconds.
  @Nullable private final Long totalNormalStateDurationMillis;

  // The total warning state duration in milliseconds.
  @Nullable private final Long totalWarningStateDurationMillis;

  // The string representation of the current severity duration.
  @Nullable private final String currentSeverityDurationString;

  // The name for the gauge.
  @Nullable private final String gaugeName;

  // The string representation of the last critical state duration.
  @Nullable private final String lastCriticalStateDurationString;

  // The string representation of the last major state duration.
  @Nullable private final String lastMajorStateDurationString;

  // The string representation of the last minor state duration.
  @Nullable private final String lastMinorStateDurationString;

  // The string representation of the last normal state duration.
  @Nullable private final String lastNormalStateDurationString;

  // The string representation of the last warning state duration.
  @Nullable private final String lastWarningStateDurationString;

  // The resource for the gauge.
  @Nullable private final String resource;

  // The resource type for the gauge.
  @Nullable private final String resourceType;

  // The summary message.
  @Nullable private final String summary;

  // The string representation of the total critical state duration.
  @Nullable private final String totalCriticalStateDurationString;

  // The string representation of the total major state duration.
  @Nullable private final String totalMajorStateDurationString;

  // The string representation of the total minor state duration.
  @Nullable private final String totalMinorStateDurationString;

  // The string representation of the total normal state duration.
  @Nullable private final String totalNormalStateDurationString;

  // The string representation of the total warning state duration.
  @Nullable private final String totalWarningStateDurationString;



  /**
   * Creates a new gauge monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a gauge monitor entry.  It must
   *                not be {@code null}.
   */
  public GaugeMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    gaugeName = getString("gauge-name");
    resource = getString("resource");
    resourceType = getString("resource-type");

    final String currentSeverityStr = getString("severity");
    if (currentSeverityStr == null)
    {
      currentSeverity = null;
    }
    else
    {
      currentSeverity = AlarmSeverity.forName(currentSeverityStr);
    }

    final String previousSeverityStr = getString("previous-severity");
    if (previousSeverityStr == null)
    {
      previousSeverity = null;
    }
    else
    {
      previousSeverity = AlarmSeverity.forName(previousSeverityStr);
    }

    summary = getString("summary");
    errorMessages = getStrings("error-message");
    initTime = getDate("gauge-init-time");
    updateTime = getDate("update-time");
    samplesThisInterval = getLong("samples-this-interval");

    currentSeverityStartTime = getDate("current-severity-start-time");
    currentSeverityDurationString = getString("current-severity-duration");
    currentSeverityDurationMillis = getLong("current-severity-duration-millis");

    lastNormalStateStartTime = getDate("last-normal-state-start-time");
    lastNormalStateEndTime = getDate("last-normal-state-end-time");
    lastNormalStateDurationString = getString("last-normal-state-duration");
    lastNormalStateDurationMillis =
         getLong("last-normal-state-duration-millis");
    totalNormalStateDurationString = getString("total-normal-state-duration");
    totalNormalStateDurationMillis =
         getLong("total-normal-state-duration-millis");

    lastWarningStateStartTime = getDate("last-warning-state-start-time");
    lastWarningStateEndTime = getDate("last-warning-state-end-time");
    lastWarningStateDurationString = getString("last-warning-state-duration");
    lastWarningStateDurationMillis =
         getLong("last-warning-state-duration-millis");
    totalWarningStateDurationString = getString("total-warning-state-duration");
    totalWarningStateDurationMillis =
         getLong("total-warning-state-duration-millis");

    lastMinorStateStartTime = getDate("last-minor-state-start-time");
    lastMinorStateEndTime = getDate("last-minor-state-end-time");
    lastMinorStateDurationString = getString("last-minor-state-duration");
    lastMinorStateDurationMillis = getLong("last-minor-state-duration-millis");
    totalMinorStateDurationString = getString("total-minor-state-duration");
    totalMinorStateDurationMillis =
         getLong("total-minor-state-duration-millis");

    lastMajorStateStartTime = getDate("last-major-state-start-time");
    lastMajorStateEndTime = getDate("last-major-state-end-time");
    lastMajorStateDurationString = getString("last-major-state-duration");
    lastMajorStateDurationMillis = getLong("last-major-state-duration-millis");
    totalMajorStateDurationString = getString("total-major-state-duration");
    totalMajorStateDurationMillis =
         getLong("total-major-state-duration-millis");

    lastCriticalStateStartTime = getDate("last-critical-state-start-time");
    lastCriticalStateEndTime = getDate("last-critical-state-end-time");
    lastCriticalStateDurationString = getString("last-critical-state-duration");
    lastCriticalStateDurationMillis =
         getLong("last-critical-state-duration-millis");
    totalCriticalStateDurationString =
         getString("total-critical-state-duration");
    totalCriticalStateDurationMillis =
         getLong("total-critical-state-duration-millis");
  }



  /**
   * Retrieves the name for the gauge, if available.
   *
   * @return  The name for the gauge, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public final String getGaugeName()
  {
    return gaugeName;
  }



  /**
   * Retrieves the resource for the gauge, if available.
   *
   * @return  The resource for the gauge, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public final String getResource()
  {
    return resource;
  }



  /**
   * Retrieves the resource type for the gauge, if available.
   *
   * @return  The resource type for the gauge, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public final String getResourceType()
  {
    return resourceType;
  }



  /**
   * Retrieves the current severity for the gauge, if available.
   *
   * @return  The current severity for the gauge, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public final AlarmSeverity getCurrentSeverity()
  {
    return currentSeverity;
  }



  /**
   * Retrieves the previous severity for the gauge, if available.
   *
   * @return  The previous severity for the gauge, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public final AlarmSeverity getPreviousSeverity()
  {
    return previousSeverity;
  }



  /**
   * Retrieves the summary message for the gauge, if available.
   *
   * @return  The summary message for the gauge, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public final String getSummary()
  {
    return summary;
  }



  /**
   * Retrieves the error messages for the gauge, if available.
   *
   * @return  The list of error messages for the gauge, or an empty list if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public final List<String> getErrorMessages()
  {
    return errorMessages;
  }



  /**
   * Retrieves the time the gauge was initialized, if available.
   *
   * @return  The time the gauge was initialized, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public final Date getInitTime()
  {
    return initTime;
  }



  /**
   * Retrieves the time the gauge was last updated, if available.
   *
   * @return  The time the gauge was last updated, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public final Date getUpdateTime()
  {
    return updateTime;
  }



  /**
   * Retrieves the number of samples taken in the current interval, if
   * available.
   *
   * @return  The number of samples taken in the current interval, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final Long getSamplesThisInterval()
  {
    return samplesThisInterval;
  }



  /**
   * Retrieves the time the gauge entered the current severity, if available.
   *
   * @return  The time the gauge entered the current severity, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getCurrentSeverityStartTime()
  {
    return currentSeverityStartTime;
  }



  /**
   * Retrieves the current severity duration as a human-readable string, if
   * available.
   *
   * @return  The current severity duration as a human-readable string, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final String getCurrentSeverityDurationString()
  {
    return currentSeverityDurationString;
  }



  /**
   * Retrieves the current severity duration in milliseconds, if available.
   *
   * @return  The current severity duration in milliseconds, or {@code null} if
   *          it was not included in the monitor entry.
   */
  @Nullable()
  public final Long getCurrentSeverityDurationMillis()
  {
    return currentSeverityDurationMillis;
  }



  /**
   * Retrieves the time the gauge last entered the normal state, if available.
   *
   * @return  The time the gauge last entered the normal state, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getLastNormalStateStartTime()
  {
    return lastNormalStateStartTime;
  }



  /**
   * Retrieves the time the gauge last exited the normal state, if available.
   *
   * @return  The time the gauge last exited the normal state, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getLastNormalStateEndTime()
  {
    return lastNormalStateEndTime;
  }



  /**
   * Retrieves the duration of the last normal state as a human-readable string,
   * if available.
   *
   * @return  The duration of the last normal state as a human-readable string,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final String getLastNormalStateDurationString()
  {
    return lastNormalStateDurationString;
  }



  /**
   * Retrieves the duration of the last normal state in milliseconds, if
   * available.
   *
   * @return  The duration of the last normal state in milliseconds, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final Long getLastNormalStateDurationMillis()
  {
    return lastNormalStateDurationMillis;
  }



  /**
   * Retrieves the total length of time the gauge has been in the normal state
   * as a human-readable string, if available.
   *
   * @return  The total length of time the gauge has been in the normal state as
   *          a human-readable string, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public final String getTotalNormalStateDurationString()
  {
    return totalNormalStateDurationString;
  }



  /**
   * Retrieves the total length of time the gauge has been in the normal state
   * in milliseconds, if available.
   *
   * @return  The total length of time the gauge has been in the normal state in
   *          milliseconds, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public final Long getTotalNormalStateDurationMillis()
  {
    return totalNormalStateDurationMillis;
  }



  /**
   * Retrieves the time the gauge last entered the warning state, if available.
   *
   * @return  The time the gauge last entered the warning state, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getLastWarningStateStartTime()
  {
    return lastWarningStateStartTime;
  }



  /**
   * Retrieves the time the gauge last exited the warning state, if available.
   *
   * @return  The time the gauge last exited the warning state, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getLastWarningStateEndTime()
  {
    return lastWarningStateEndTime;
  }



  /**
   * Retrieves the duration of the last warning state as a human-readable
   * string, if available.
   *
   * @return  The duration of the last warning state as a human-readable string,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final String getLastWarningStateDurationString()
  {
    return lastWarningStateDurationString;
  }



  /**
   * Retrieves the duration of the last warning state in milliseconds, if
   * available.
   *
   * @return  The duration of the last warning state in milliseconds, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final Long getLastWarningStateDurationMillis()
  {
    return lastWarningStateDurationMillis;
  }



  /**
   * Retrieves the total length of time the gauge has been in the warning state
   * as a human-readable string, if available.
   *
   * @return  The total length of time the gauge has been in the warning state
   *          as a human-readable string, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public final String getTotalWarningStateDurationString()
  {
    return totalWarningStateDurationString;
  }



  /**
   * Retrieves the total length of time the gauge has been in the warning state
   * in milliseconds, if available.
   *
   * @return  The total length of time the gauge has been in the warning state
   *          in milliseconds, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public final Long getTotalWarningStateDurationMillis()
  {
    return totalWarningStateDurationMillis;
  }



  /**
   * Retrieves the time the gauge last entered the minor state, if available.
   *
   * @return  The time the gauge last entered the minor state, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getLastMinorStateStartTime()
  {
    return lastMinorStateStartTime;
  }



  /**
   * Retrieves the time the gauge last exited the minor state, if available.
   *
   * @return  The time the gauge last exited the minor state, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getLastMinorStateEndTime()
  {
    return lastMinorStateEndTime;
  }



  /**
   * Retrieves the duration of the last minor state as a human-readable string,
   * if available.
   *
   * @return  The duration of the last minor state as a human-readable string,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final String getLastMinorStateDurationString()
  {
    return lastMinorStateDurationString;
  }



  /**
   * Retrieves the duration of the last minor state in milliseconds, if
   * available.
   *
   * @return  The duration of the last minor state in milliseconds, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final Long getLastMinorStateDurationMillis()
  {
    return lastMinorStateDurationMillis;
  }



  /**
   * Retrieves the total length of time the gauge has been in the minor state
   * as a human-readable string, if available.
   *
   * @return  The total length of time the gauge has been in the minor state as
   *          a human-readable string, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public final String getTotalMinorStateDurationString()
  {
    return totalMinorStateDurationString;
  }



  /**
   * Retrieves the total length of time the gauge has been in the minor state
   * in milliseconds, if available.
   *
   * @return  The total length of time the gauge has been in the minor state in
   *          milliseconds, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public final Long getTotalMinorStateDurationMillis()
  {
    return totalMinorStateDurationMillis;
  }



  /**
   * Retrieves the time the gauge last entered the major state, if available.
   *
   * @return  The time the gauge last entered the major state, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getLastMajorStateStartTime()
  {
    return lastMajorStateStartTime;
  }



  /**
   * Retrieves the time the gauge last exited the major state, if available.
   *
   * @return  The time the gauge last exited the major state, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getLastMajorStateEndTime()
  {
    return lastMajorStateEndTime;
  }



  /**
   * Retrieves the duration of the last major state as a human-readable string,
   * if available.
   *
   * @return  The duration of the last major state as a human-readable string,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final String getLastMajorStateDurationString()
  {
    return lastMajorStateDurationString;
  }



  /**
   * Retrieves the duration of the last major state in milliseconds, if
   * available.
   *
   * @return  The duration of the last major state in milliseconds, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final Long getLastMajorStateDurationMillis()
  {
    return lastMajorStateDurationMillis;
  }



  /**
   * Retrieves the total length of time the gauge has been in the major state
   * as a human-readable string, if available.
   *
   * @return  The total length of time the gauge has been in the major state as
   *          a human-readable string, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public final String getTotalMajorStateDurationString()
  {
    return totalMajorStateDurationString;
  }



  /**
   * Retrieves the total length of time the gauge has been in the major state
   * in milliseconds, if available.
   *
   * @return  The total length of time the gauge has been in the major state in
   *          milliseconds, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public final Long getTotalMajorStateDurationMillis()
  {
    return totalMajorStateDurationMillis;
  }



  /**
   * Retrieves the time the gauge last entered the critical state, if available.
   *
   * @return  The time the gauge last entered the critical state, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getLastCriticalStateStartTime()
  {
    return lastCriticalStateStartTime;
  }



  /**
   * Retrieves the time the gauge last exited the critical state, if available.
   *
   * @return  The time the gauge last exited the critical state, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public final Date getLastCriticalStateEndTime()
  {
    return lastCriticalStateEndTime;
  }



  /**
   * Retrieves the duration of the last critical state as a human-readable
   * string, if available.
   *
   * @return  The duration of the last critical state as a human-readable
   *          string, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public final String getLastCriticalStateDurationString()
  {
    return lastCriticalStateDurationString;
  }



  /**
   * Retrieves the duration of the last critical state in milliseconds, if
   * available.
   *
   * @return  The duration of the last critical state in milliseconds, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public final Long getLastCriticalStateDurationMillis()
  {
    return lastCriticalStateDurationMillis;
  }



  /**
   * Retrieves the total length of time the gauge has been in the critical state
   * as a human-readable string, if available.
   *
   * @return  The total length of time the gauge has been in the critical state
   *          as a human-readable string, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public final String getTotalCriticalStateDurationString()
  {
    return totalCriticalStateDurationString;
  }



  /**
   * Retrieves the total length of time the gauge has been in the critical state
   * in milliseconds, if available.
   *
   * @return  The total length of time the gauge has been in the critical state
   *          in milliseconds, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public final Long getTotalCriticalStateDurationMillis()
  {
    return totalCriticalStateDurationMillis;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_GAUGE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_GAUGE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(43));

    if (gaugeName != null)
    {
      addMonitorAttribute(attrs,
           "gauge-name",
           INFO_GAUGE_DISPNAME_GAUGE_NAME.get(),
           INFO_GAUGE_DESC_GAUGE_NAME.get(),
           gaugeName);
    }

    if (resource != null)
    {
      addMonitorAttribute(attrs,
           "resource",
           INFO_GAUGE_DISPNAME_RESOURCE.get(),
           INFO_GAUGE_DESC_RESOURCE.get(),
           resource);
    }

    if (resourceType != null)
    {
      addMonitorAttribute(attrs,
           "resource-type",
           INFO_GAUGE_DISPNAME_RESOURCE_TYPE.get(),
           INFO_GAUGE_DESC_RESOURCE_TYPE.get(),
           resourceType);
    }

    if (currentSeverity != null)
    {
      addMonitorAttribute(attrs,
           "severity",
           INFO_GAUGE_DISPNAME_CURRENT_SEVERITY.get(),
           INFO_GAUGE_DESC_CURRENT_SEVERITY.get(),
           currentSeverity.name());
    }

    if (previousSeverity != null)
    {
      addMonitorAttribute(attrs,
           "previous-severity",
           INFO_GAUGE_DISPNAME_PREVIOUS_SEVERITY.get(),
           INFO_GAUGE_DESC_PREVIOUS_SEVERITY.get(),
           previousSeverity.name());
    }

    if (summary != null)
    {
      addMonitorAttribute(attrs,
           "summary",
           INFO_GAUGE_DISPNAME_SUMMARY.get(),
           INFO_GAUGE_DESC_SUMMARY.get(),
           summary);
    }

    if (! errorMessages.isEmpty())
    {
      addMonitorAttribute(attrs,
           "error-message",
           INFO_GAUGE_DISPNAME_ERROR_MESSAGE.get(),
           INFO_GAUGE_DESC_ERROR_MESSAGE.get(),
           errorMessages);
    }

    if (initTime != null)
    {
      addMonitorAttribute(attrs,
           "gauge-init-time",
           INFO_GAUGE_DISPNAME_INIT_TIME.get(),
           INFO_GAUGE_DESC_INIT_TIME.get(),
           initTime);
    }

    if (updateTime != null)
    {
      addMonitorAttribute(attrs,
           "update-time",
           INFO_GAUGE_DISPNAME_UPDATE_TIME.get(),
           INFO_GAUGE_DESC_UPDATE_TIME.get(),
           updateTime);
    }

    if (samplesThisInterval != null)
    {
      addMonitorAttribute(attrs,
           "samples-this-interval",
           INFO_GAUGE_DISPNAME_SAMPLES_THIS_INTERVAL.get(),
           INFO_GAUGE_DESC_SAMPLES_THIS_INTERVAL.get(),
           samplesThisInterval);
    }

    if (currentSeverityStartTime != null)
    {
      addMonitorAttribute(attrs,
           "current-severity-start-time",
           INFO_GAUGE_DISPNAME_CURRENT_START_TIME.get(),
           INFO_GAUGE_DESC_CURRENT_START_TIME.get(),
           currentSeverityStartTime);
    }

    if (currentSeverityDurationString != null)
    {
      addMonitorAttribute(attrs,
           "current-severity-duration",
           INFO_GAUGE_DISPNAME_CURRENT_DURATION_STRING.get(),
           INFO_GAUGE_DESC_CURRENT_DURATION_STRING.get(),
           currentSeverityDurationString);
    }

    if (currentSeverityDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "current-severity-duration-millis",
           INFO_GAUGE_DISPNAME_CURRENT_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_CURRENT_DURATION_MILLIS.get(),
           currentSeverityDurationMillis);
    }

    if (lastNormalStateStartTime != null)
    {
      addMonitorAttribute(attrs,
           "last-normal-state-start-time",
           INFO_GAUGE_DISPNAME_LAST_NORMAL_START_TIME.get(),
           INFO_GAUGE_DESC_LAST_NORMAL_START_TIME.get(),
           lastNormalStateStartTime);
    }

    if (lastNormalStateEndTime != null)
    {
      addMonitorAttribute(attrs,
           "last-normal-state-end-time",
           INFO_GAUGE_DISPNAME_LAST_NORMAL_END_TIME.get(),
           INFO_GAUGE_DESC_LAST_NORMAL_END_TIME.get(),
           lastNormalStateEndTime);
    }

    if (lastNormalStateDurationString != null)
    {
      addMonitorAttribute(attrs,
           "last-normal-state-duration",
           INFO_GAUGE_DISPNAME_LAST_NORMAL_DURATION_STRING.get(),
           INFO_GAUGE_DESC_LAST_NORMAL_DURATION_STRING.get(),
           lastNormalStateDurationString);
    }

    if (lastNormalStateDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "last-normal-state-duration-millis",
           INFO_GAUGE_DISPNAME_LAST_NORMAL_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_LAST_NORMAL_DURATION_MILLIS.get(),
           lastNormalStateDurationMillis);
    }

    if (totalNormalStateDurationString != null)
    {
      addMonitorAttribute(attrs,
           "total-normal-state-duration",
           INFO_GAUGE_DISPNAME_TOTAL_NORMAL_DURATION_STRING.get(),
           INFO_GAUGE_DESC_TOTAL_NORMAL_DURATION_STRING.get(),
           totalNormalStateDurationString);
    }

    if (totalNormalStateDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "total-normal-state-duration-millis",
           INFO_GAUGE_DISPNAME_TOTAL_NORMAL_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_TOTAL_NORMAL_DURATION_MILLIS.get(),
           totalNormalStateDurationMillis);
    }

    if (lastWarningStateStartTime != null)
    {
      addMonitorAttribute(attrs,
           "last-warning-state-start-time",
           INFO_GAUGE_DISPNAME_LAST_WARNING_START_TIME.get(),
           INFO_GAUGE_DESC_LAST_WARNING_START_TIME.get(),
           lastWarningStateStartTime);
    }

    if (lastWarningStateEndTime != null)
    {
      addMonitorAttribute(attrs,
           "last-warning-state-end-time",
           INFO_GAUGE_DISPNAME_LAST_WARNING_END_TIME.get(),
           INFO_GAUGE_DESC_LAST_WARNING_END_TIME.get(),
           lastWarningStateEndTime);
    }

    if (lastWarningStateDurationString != null)
    {
      addMonitorAttribute(attrs,
           "last-warning-state-duration",
           INFO_GAUGE_DISPNAME_LAST_WARNING_DURATION_STRING.get(),
           INFO_GAUGE_DESC_LAST_WARNING_DURATION_STRING.get(),
           lastWarningStateDurationString);
    }

    if (lastWarningStateDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "last-warning-state-duration-millis",
           INFO_GAUGE_DISPNAME_LAST_WARNING_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_LAST_WARNING_DURATION_MILLIS.get(),
           lastWarningStateDurationMillis);
    }

    if (totalWarningStateDurationString != null)
    {
      addMonitorAttribute(attrs,
           "total-warning-state-duration",
           INFO_GAUGE_DISPNAME_TOTAL_WARNING_DURATION_STRING.get(),
           INFO_GAUGE_DESC_TOTAL_WARNING_DURATION_STRING.get(),
           totalWarningStateDurationString);
    }

    if (totalWarningStateDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "total-warning-state-duration-millis",
           INFO_GAUGE_DISPNAME_TOTAL_WARNING_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_TOTAL_WARNING_DURATION_MILLIS.get(),
           totalWarningStateDurationMillis);
    }

    if (lastMinorStateStartTime != null)
    {
      addMonitorAttribute(attrs,
           "last-minor-state-start-time",
           INFO_GAUGE_DISPNAME_LAST_MINOR_START_TIME.get(),
           INFO_GAUGE_DESC_LAST_MINOR_START_TIME.get(),
           lastMinorStateStartTime);
    }

    if (lastMinorStateEndTime != null)
    {
      addMonitorAttribute(attrs,
           "last-minor-state-end-time",
           INFO_GAUGE_DISPNAME_LAST_MINOR_END_TIME.get(),
           INFO_GAUGE_DESC_LAST_MINOR_END_TIME.get(),
           lastMinorStateEndTime);
    }

    if (lastMinorStateDurationString != null)
    {
      addMonitorAttribute(attrs,
           "last-minor-state-duration",
           INFO_GAUGE_DISPNAME_LAST_MINOR_DURATION_STRING.get(),
           INFO_GAUGE_DESC_LAST_MINOR_DURATION_STRING.get(),
           lastMinorStateDurationString);
    }

    if (lastMinorStateDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "last-minor-state-duration-millis",
           INFO_GAUGE_DISPNAME_LAST_MINOR_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_LAST_MINOR_DURATION_MILLIS.get(),
           lastMinorStateDurationMillis);
    }

    if (totalMinorStateDurationString != null)
    {
      addMonitorAttribute(attrs,
           "total-minor-state-duration",
           INFO_GAUGE_DISPNAME_TOTAL_MINOR_DURATION_STRING.get(),
           INFO_GAUGE_DESC_TOTAL_MINOR_DURATION_STRING.get(),
           totalMinorStateDurationString);
    }

    if (totalMinorStateDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "total-minor-state-duration-millis",
           INFO_GAUGE_DISPNAME_TOTAL_MINOR_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_TOTAL_MINOR_DURATION_MILLIS.get(),
           totalMinorStateDurationMillis);
    }

    if (lastMajorStateStartTime != null)
    {
      addMonitorAttribute(attrs,
           "last-major-state-start-time",
           INFO_GAUGE_DISPNAME_LAST_MAJOR_START_TIME.get(),
           INFO_GAUGE_DESC_LAST_MAJOR_START_TIME.get(),
           lastMajorStateStartTime);
    }

    if (lastMajorStateEndTime != null)
    {
      addMonitorAttribute(attrs,
           "last-major-state-end-time",
           INFO_GAUGE_DISPNAME_LAST_MAJOR_END_TIME.get(),
           INFO_GAUGE_DESC_LAST_MAJOR_END_TIME.get(),
           lastMajorStateEndTime);
    }

    if (lastMajorStateDurationString != null)
    {
      addMonitorAttribute(attrs,
           "last-major-state-duration",
           INFO_GAUGE_DISPNAME_LAST_MAJOR_DURATION_STRING.get(),
           INFO_GAUGE_DESC_LAST_MAJOR_DURATION_STRING.get(),
           lastMajorStateDurationString);
    }

    if (lastMajorStateDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "last-major-state-duration-millis",
           INFO_GAUGE_DISPNAME_LAST_MAJOR_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_LAST_MAJOR_DURATION_MILLIS.get(),
           lastMajorStateDurationMillis);
    }

    if (totalMajorStateDurationString != null)
    {
      addMonitorAttribute(attrs,
           "total-major-state-duration",
           INFO_GAUGE_DISPNAME_TOTAL_MAJOR_DURATION_STRING.get(),
           INFO_GAUGE_DESC_TOTAL_MAJOR_DURATION_STRING.get(),
           totalMajorStateDurationString);
    }

    if (totalMajorStateDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "total-major-state-duration-millis",
           INFO_GAUGE_DISPNAME_TOTAL_MAJOR_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_TOTAL_MAJOR_DURATION_MILLIS.get(),
           totalMajorStateDurationMillis);
    }

    if (lastCriticalStateStartTime != null)
    {
      addMonitorAttribute(attrs,
           "last-critical-state-start-time",
           INFO_GAUGE_DISPNAME_LAST_CRITICAL_START_TIME.get(),
           INFO_GAUGE_DESC_LAST_CRITICAL_START_TIME.get(),
           lastCriticalStateStartTime);
    }

    if (lastCriticalStateEndTime != null)
    {
      addMonitorAttribute(attrs,
           "last-critical-state-end-time",
           INFO_GAUGE_DISPNAME_LAST_CRITICAL_END_TIME.get(),
           INFO_GAUGE_DESC_LAST_CRITICAL_END_TIME.get(),
           lastCriticalStateEndTime);
    }

    if (lastCriticalStateDurationString != null)
    {
      addMonitorAttribute(attrs,
           "last-critical-state-duration",
           INFO_GAUGE_DISPNAME_LAST_CRITICAL_DURATION_STRING.get(),
           INFO_GAUGE_DESC_LAST_CRITICAL_DURATION_STRING.get(),
           lastCriticalStateDurationString);
    }

    if (lastCriticalStateDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "last-critical-state-duration-millis",
           INFO_GAUGE_DISPNAME_LAST_CRITICAL_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_LAST_CRITICAL_DURATION_MILLIS.get(),
           lastCriticalStateDurationMillis);
    }

    if (totalCriticalStateDurationString != null)
    {
      addMonitorAttribute(attrs,
           "total-critical-state-duration",
           INFO_GAUGE_DISPNAME_TOTAL_CRITICAL_DURATION_STRING.get(),
           INFO_GAUGE_DESC_TOTAL_CRITICAL_DURATION_STRING.get(),
           totalCriticalStateDurationString);
    }

    if (totalCriticalStateDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           "total-critical-state-duration-millis",
           INFO_GAUGE_DISPNAME_TOTAL_CRITICAL_DURATION_MILLIS.get(),
           INFO_GAUGE_DESC_TOTAL_CRITICAL_DURATION_MILLIS.get(),
           totalCriticalStateDurationMillis);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
