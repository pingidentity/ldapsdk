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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.Date;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure for representing an administrative entry
 * as exposed by the alarms backend in the Directory Server.  Alarm entries
 * provide information about potential ongoing or resolved conditions within the
 * server.
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
public final class AlarmEntry
       extends ReadOnlyEntry
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2481622467368820030L;



  // The current severity for this alarm entry.
  @Nullable private final AlarmSeverity currentSeverity;

  // The previous severity for this alarm entry.
  @Nullable private final AlarmSeverity previousSeverity;

  // The last time the alarm severity was set to critical.
  @Nullable private final Date lastCriticalTime;

  // The last time the alarm severity was set to indeterminate.
  @Nullable private final Date lastIndeterminateTime;

  // The last time the alarm severity was set to major.
  @Nullable private final Date lastMajorTime;

  // The last time the alarm severity was set to minor.
  @Nullable private final Date lastMinorTime;

  // The last time the alarm severity was set to normal.
  @Nullable private final Date lastNormalTime;

  // The last time the alarm severity was set to warning.
  @Nullable private final Date lastWarningTime;

  // The start time for this alarm entry.
  @Nullable private final Date startTime;

  // The X.733 event type for the alarm.
  @Nullable private final Integer eventType;

  // The X.733 probable cause for the alarm.
  @Nullable private final Integer probableCause;

  // The total length of time in milliseconds spent at the critical severity.
  @Nullable private final Long totalDurationCriticalMillis;

  // The total length of time in milliseconds spent at the indeterminate
  // severity.
  @Nullable private final Long totalDurationIndeterminateMillis;

  // The total length of time in milliseconds spent at the major severity.
  @Nullable private final Long totalDurationMajorMillis;

  // The total length of time in milliseconds spent at the minor severity.
  @Nullable private final Long totalDurationMinorMillis;

  // The total length of time in milliseconds spent at the normal severity.
  @Nullable private final Long totalDurationNormalMillis;

  // The total length of time in milliseconds spent at the warning severity.
  @Nullable private final Long totalDurationWarningMillis;

  // The additional text for this alarm entry.
  @Nullable private final String additionalText;

  // The condition for this alarm entry.
  @Nullable private final String condition;

  // The details for this alarm entry.
  @Nullable private final String details;

  // The identifier for this alarm entry.
  @Nullable private final String id;

  // The specific resource for this alarm entry.
  @Nullable private final String specificResource;

  // The specific resource type for this alarm entry.
  @Nullable private final String specificResourceType;



  /**
   * Creates a new alarm entry from the provided entry.
   *
   * @param  entry  The entry to use to create this alarm entry.
   */
  public AlarmEntry(@NotNull final Entry entry)
  {
    super(entry);

    id = entry.getAttributeValue("ds-alarm-id");
    condition = entry.getAttributeValue("ds-alarm-condition");
    startTime = entry.getAttributeValueAsDate("ds-alarm-start-time");
    specificResource = entry.getAttributeValue("ds-alarm-specific-resource");
    specificResourceType =
         entry.getAttributeValue("ds-alarm-specific-resource-type");
    details = entry.getAttributeValue("ds-alarm-details");
    additionalText = entry.getAttributeValue("ds-alarm-additional-text");
    lastNormalTime = entry.getAttributeValueAsDate("ds-alarm-normal-last-time");
    lastWarningTime =
         entry.getAttributeValueAsDate("ds-alarm-warning-last-time");
    lastMinorTime = entry.getAttributeValueAsDate("ds-alarm-minor-last-time");
    lastMajorTime = entry.getAttributeValueAsDate("ds-alarm-major-last-time");
    lastCriticalTime =
         entry.getAttributeValueAsDate("ds-alarm-critical-last-time");
    lastIndeterminateTime =
         entry.getAttributeValueAsDate("ds-alarm-indeterminate-last-time");
    totalDurationNormalMillis =
         entry.getAttributeValueAsLong("ds-alarm-normal-total-duration-millis");
    totalDurationWarningMillis = entry.getAttributeValueAsLong(
         "ds-alarm-warning-total-duration-millis");
    totalDurationMinorMillis =
         entry.getAttributeValueAsLong("ds-alarm-minor-total-duration-millis");
    totalDurationMajorMillis =
         entry.getAttributeValueAsLong("ds-alarm-major-total-duration-millis");
    totalDurationCriticalMillis = entry.getAttributeValueAsLong(
         "ds-alarm-critical-total-duration-millis");
    totalDurationIndeterminateMillis = entry.getAttributeValueAsLong(
         "ds-alarm-indeterminate-total-duration-millis");
    eventType = entry.getAttributeValueAsInteger("ds-alarm-event-type");
    probableCause = entry.getAttributeValueAsInteger("ds-alarm-probable-cause");

    final String currentSeverityStr =
         entry.getAttributeValue("ds-alarm-severity");
    if (currentSeverityStr == null)
    {
      currentSeverity = null;
    }
    else
    {
      currentSeverity = AlarmSeverity.forName(currentSeverityStr);
    }

    final String previousSeverityStr =
         entry.getAttributeValue("ds-alarm-previous-severity");
    if (previousSeverityStr == null)
    {
      previousSeverity = null;
    }
    else
    {
      previousSeverity = AlarmSeverity.forName(previousSeverityStr);
    }
  }



  /**
   * Retrieves the identifier for the alarm.
   *
   * @return  The identifier for the alarm, or {@code null} if it was not
   *          included in the alarm entry.
   */
  @Nullable()
  public String getAlarmID()
  {
    return id;
  }



  /**
   * Retrieves the condition for the alarm.
   *
   * @return  The condition for the alarm, or {@code null} if it was not
   *          included in the alarm entry.
   */
  @Nullable()
  public String getAlarmCondition()
  {
    return condition;
  }



  /**
   * Retrieves the current severity for the alarm.
   *
   * @return  The current severity for the alarm, or {@code null} if it was not
   *          included in the alarm entry.
   */
  @Nullable()
  public AlarmSeverity getCurrentAlarmSeverity()
  {
    return currentSeverity;
  }



  /**
   * Retrieves the previous severity for the alarm.
   *
   * @return  The previous severity for the alarm, or {@code null} if it was not
   *          included in the alarm entry.
   */
  @Nullable()
  public AlarmSeverity getPreviousAlarmSeverity()
  {
    return previousSeverity;
  }



  /**
   * Retrieves the start time for the alarm.
   *
   * @return  The start time for the alarm, or {@code null} if it was not
   *          included in the alarm entry.
   */
  @Nullable()
  public Date getAlarmStartTime()
  {
    return startTime;
  }



  /**
   * Retrieves the specific resource for the alarm, if any.
   *
   * @return  The specific resource for the alarm, or {@code null} if it was not
   *          included in the alarm entry.
   */
  @Nullable()
  public String getAlarmSpecificResource()
  {
    return specificResource;
  }



  /**
   * Retrieves the specific resource type for the alarm, if any.
   *
   * @return  The specific resource type for the alarm, or {@code null} if it
   *          was not included in the alarm entry.
   */
  @Nullable()
  public String getAlarmSpecificResourceType()
  {
    return specificResourceType;
  }



  /**
   * Retrieves the details message for the alarm, if any.
   *
   * @return  The details message for the alarm, or {@code null} if it was not
   *          included in the alarm entry.
   */
  @Nullable()
  public String getAlarmDetails()
  {
    return details;
  }



  /**
   * Retrieves the additional text for the alarm, if any.
   *
   * @return  The additional text for the alarm, or {@code null} if it was not
   *          included in the alarm entry.
   */
  @Nullable()
  public String getAlarmAdditionalText()
  {
    return additionalText;
  }



  /**
   * Retrieves the time that the alarm last transitioned to a normal severity,
   * if available.
   *
   * @return  The time that the alarm last transitioned to a normal severity, or
   *          {@code null} if it was not included in the alarm entry.
   */
  @Nullable()
  public Date getAlarmLastNormalTime()
  {
    return lastNormalTime;
  }



  /**
   * Retrieves the time that the alarm last transitioned to a warning severity,
   * if available.
   *
   * @return  The time that the alarm last transitioned to a warning severity,
   *          or {@code null} if it was not included in the alarm entry.
   */
  @Nullable()
  public Date getAlarmLastWarningTime()
  {
    return lastWarningTime;
  }



  /**
   * Retrieves the time that the alarm last transitioned to a minor severity,
   * if available.
   *
   * @return  The time that the alarm last transitioned to a minor severity, or
   *          {@code null} if it was not included in the alarm entry.
   */
  @Nullable()
  public Date getAlarmLastMinorTime()
  {
    return lastMinorTime;
  }



  /**
   * Retrieves the time that the alarm last transitioned to a major severity,
   * if available.
   *
   * @return  The time that the alarm last transitioned to a major severity, or
   *          {@code null} if it was not included in the alarm entry.
   */
  @Nullable()
  public Date getAlarmLastMajorTime()
  {
    return lastMajorTime;
  }



  /**
   * Retrieves the time that the alarm last transitioned to a critical severity,
   * if available.
   *
   * @return  The time that the alarm last transitioned to a critical severity,
   *          or {@code null} if it was not included in the alarm entry.
   */
  @Nullable()
  public Date getAlarmLastCriticalTime()
  {
    return lastCriticalTime;
  }



  /**
   * Retrieves the time that the alarm last transitioned to an indeterminate
   * severity, if available.
   *
   * @return  The time that the alarm last transitioned to an indeterminate
   *          severity, or {@code null} if it was not included in the alarm
   *          entry.
   */
  @Nullable()
  public Date getAlarmLastIndeterminateTime()
  {
    return lastIndeterminateTime;
  }



  /**
   * Retrieves the length of time in milliseconds the alarm has spent at the
   * normal severity, if available.
   *
   * @return  The length of time in milliseconds the alarm has spent at the
   *          normal severity, or {@code null} if it was not included in the
   *          alarm entry.
   */
  @Nullable()
  public Long getAlarmTotalDurationNormalMillis()
  {
    return totalDurationNormalMillis;
  }



  /**
   * Retrieves the length of time in milliseconds the alarm has spent at the
   * warning severity, if available.
   *
   * @return  The length of time in milliseconds the alarm has spent at the
   *          warning severity, or {@code null} if it was not included in the
   *          alarm entry.
   */
  @Nullable()
  public Long getAlarmTotalDurationWarningMillis()
  {
    return totalDurationWarningMillis;
  }



  /**
   * Retrieves the length of time in milliseconds the alarm has spent at the
   * minor severity, if available.
   *
   * @return  The length of time in milliseconds the alarm has spent at the
   *          minor severity, or {@code null} if it was not included in the
   *          alarm entry.
   */
  @Nullable()
  public Long getAlarmTotalDurationMinorMillis()
  {
    return totalDurationMinorMillis;
  }



  /**
   * Retrieves the length of time in milliseconds the alarm has spent at the
   * major severity, if available.
   *
   * @return  The length of time in milliseconds the alarm has spent at the
   *          major severity, or {@code null} if it was not included in the
   *          alarm entry.
   */
  @Nullable()
  public Long getAlarmTotalDurationMajorMillis()
  {
    return totalDurationMajorMillis;
  }



  /**
   * Retrieves the length of time in milliseconds the alarm has spent at the
   * critical severity, if available.
   *
   * @return  The length of time in milliseconds the alarm has spent at the
   *          critical severity, or {@code null} if it was not included in the
   *          alarm entry.
   */
  @Nullable()
  public Long getAlarmTotalDurationCriticalMillis()
  {
    return totalDurationCriticalMillis;
  }



  /**
   * Retrieves the length of time in milliseconds the alarm has spent at the
   * indeterminate severity, if available.
   *
   * @return  The length of time in milliseconds the alarm has spent at the
   *          indeterminate severity, or {@code null} if it was not included in
   *          the alarm entry.
   */
  @Nullable()
  public Long getAlarmTotalDurationIndeterminateMillis()
  {
    return totalDurationIndeterminateMillis;
  }



  /**
   * Retrieves the X.733 event type for the alarm, if available.
   *
   * @return  The X.733 event type for the alarm, or {@code null} if it was not
   *          included in the alarm entry.
   */
  @Nullable()
  public Integer getAlarmEventType()
  {
    return eventType;
  }



  /**
   * Retrieves the X.733 probable cause for the alarm, if available.
   *
   * @return  The X.733 probable cause for the alarm, or {@code null} if it was
   *          not included in the alarm entry.
   */
  @Nullable()
  public Integer getAlarmProbableCause()
  {
    return probableCause;
  }
}
