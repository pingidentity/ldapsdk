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



import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a generic monitor entry that provides access to monitor
 * information provided by a Ping Identity, UnboundID, or Nokia/Alcatel-Lucent
 * 8661 server instance.  Subclasses may provide specific methods for
 * interpreting the information exposed by specific types of monitor entries.
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
 * See the {@link MonitorManager} class for an example that demonstrates the
 * process for retrieving all monitor entries available in the directory server
 * and retrieving the information they provide using the generic API.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class MonitorEntry
       implements Serializable
{
  /**
   * The object class used for all monitor entries.  Specific monitor entries
   * will have a subclass of this class.
   */
  @NotNull static final String GENERIC_MONITOR_OC = "ds-monitor-entry";



  /**
   * The base DN for all monitor entries.
   */
  @NotNull static final String MONITOR_BASE_DN = "cn=monitor";



  /**
   * The name of the attribute used to hold the name assigned to the monitor
   * entry.
   */
  @NotNull private static final String ATTR_MONITOR_NAME = "cn";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8889119758772055683L;



  // The entry containing the information used by this monitor entry object.
  @NotNull private final ReadOnlyEntry entry;

  // The monitor object class for the associated monitor entry, if available.
  @NotNull private final String monitorClass;

  // The monitor name for this monitor entry.
  @Nullable private final String monitorName;



  /**
   * Creates a new monitor entry from the information contained in the provided
   * entry.
   *
   * @param  entry  The entry providing information to use for this monitor
   *                entry.  It must not be {@code null}.
   */
  public MonitorEntry(@NotNull final Entry entry)
  {
    Validator.ensureNotNull(entry);

    this.entry = new ReadOnlyEntry(entry);

    monitorClass = getMonitorClass(entry);
    monitorName  = getString(ATTR_MONITOR_NAME);
  }



  /**
   * Retrieves the DN for this monitor entry.
   *
   * @return  The DN for this monitor entry.
   */
  @NotNull()
  public final String getDN()
  {
    return entry.getDN();
  }



  /**
   * Retrieves the {@code Entry} used to create this monitor entry.
   *
   * @return  The {@code Entry} used to create this monitor entry.
   */
  @NotNull()
  public final ReadOnlyEntry getEntry()
  {
    return entry;
  }



  /**
   * Retrieves the name of the structural object class for this monitor entry.
   *
   * @return  The name of the structural object class for this monitor entry, or
   *          the generic monitor object class if no appropriate subclass could
   *          be identified.
   */
  @NotNull()
  public final String getMonitorClass()
  {
    return monitorClass;
  }



  /**
   * Retrieves the monitor name for this monitor entry.
   *
   * @return  The monitor name for this monitor entry, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public final String getMonitorName()
  {
    return monitorName;
  }



  /**
   * Retrieves a human-readable display name for this monitor entry.
   *
   * @return  A human-readable display name for this monitor entry.
   */
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_GENERIC_MONITOR_DISPNAME.get();
  }



  /**
   * Retrieves a human-readable description name for this monitor entry.
   *
   * @return  A human-readable description name for this monitor entry.
   */
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_GENERIC_MONITOR_DESC.get();
  }



  /**
   * Retrieves the set of parsed monitor attributes for this monitor entry,
   * mapped from a unique identifier (in all lowercase characters) to the
   * corresponding monitor attribute.
   *
   * @return  The set of parsed monitor attributes for this monitor entry.
   */
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    // Retrieve a map of all attributes in the entry except cn and objectClass.
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));

    for (final Attribute a : entry.getAttributes())
    {
      final String lowerName = StaticUtils.toLowerCase(a.getName());
      if (lowerName.equals("cn") || lowerName.equals("objectclass"))
      {
        continue;
      }

      attrs.put(lowerName,
           new MonitorAttribute(lowerName, a.getName(), "", a.getValues()));
    }

    return Collections.unmodifiableMap(attrs);
  }



  /**
   * Creates a monitor entry object from the provided entry.  An attempt will be
   * made to decode the entry as an instance of the most appropriate subclass,
   * but if that is not possible then it will be parsed as a generic monitor
   * entry.
   *
   * @param  entry  The entry to be decoded as a monitor entry.
   *
   * @return  The decoded monitor entry of the appropriate subtype, or a generic
   *          monitor entry if no appropriate subclass could be identified.
   */
  @NotNull()
  public static MonitorEntry decode(@NotNull final Entry entry)
  {
    final String monitorClass = getMonitorClass(entry);

    if (monitorClass.equalsIgnoreCase(
             ActiveOperationsMonitorEntry.ACTIVE_OPERATIONS_MONITOR_OC))
    {
      return new ActiveOperationsMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  BackendMonitorEntry.BACKEND_MONITOR_OC))
    {
      return new BackendMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  ClientConnectionMonitorEntry.CLIENT_CONNECTION_MONITOR_OC))
    {
      return new ClientConnectionMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  ConnectionHandlerMonitorEntry.CONNECTION_HANDLER_MONITOR_OC))
    {
      return new ConnectionHandlerMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  DiskSpaceUsageMonitorEntry.DISK_SPACE_USAGE_MONITOR_OC))
    {
      return new DiskSpaceUsageMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  EntryCacheMonitorEntry.ENTRY_CACHE_MONITOR_OC))
    {
      return new EntryCacheMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  FIFOEntryCacheMonitorEntry.FIFO_ENTRY_CACHE_MONITOR_OC))
    {
      return new FIFOEntryCacheMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  GaugeMonitorEntry.GAUGE_MONITOR_OC))
    {
      return new GaugeMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  GeneralMonitorEntry.GENERAL_MONITOR_OC))
    {
      return new GeneralMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  GroupCacheMonitorEntry.GROUP_CACHE_MONITOR_OC))
    {
      return new GroupCacheMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
         HostSystemRecentCPUAndMemoryMonitorEntry.
              HOST_SYSTEM_RECENT_CPU_AND_MEMORY_MONITOR_OC))
    {
      return new HostSystemRecentCPUAndMemoryMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  IndexMonitorEntry.INDEX_MONITOR_OC))
    {
      return new IndexMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  IndicatorGaugeMonitorEntry.INDICATOR_GAUGE_MONITOR_OC))
    {
      return new IndicatorGaugeMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  JEEnvironmentMonitorEntry.JE_ENVIRONMENT_MONITOR_OC))
    {
      return new JEEnvironmentMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
         LDAPExternalServerMonitorEntry.LDAP_EXTERNAL_SERVER_MONITOR_OC))
    {
      return new LDAPExternalServerMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  LDAPStatisticsMonitorEntry.LDAP_STATISTICS_MONITOR_OC))
    {
      return new LDAPStatisticsMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
         LoadBalancingAlgorithmMonitorEntry.
              LOAD_BALANCING_ALGORITHM_MONITOR_OC))
    {
      return new LoadBalancingAlgorithmMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  MemoryUsageMonitorEntry.MEMORY_USAGE_MONITOR_OC))
    {
      return new MemoryUsageMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  NumericGaugeMonitorEntry.NUMERIC_GAUGE_MONITOR_OC))
    {
      return new NumericGaugeMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  PerApplicationProcessingTimeHistogramMonitorEntry.
                       PER_APPLICATION_PROCESSING_TIME_HISTOGRAM_MONITOR_OC))
    {
      return new PerApplicationProcessingTimeHistogramMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  ProcessingTimeHistogramMonitorEntry.
                       PROCESSING_TIME_HISTOGRAM_MONITOR_OC))
    {
      return new ProcessingTimeHistogramMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  ReplicaMonitorEntry.REPLICA_MONITOR_OC))
    {
      return new ReplicaMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  ReplicationServerMonitorEntry.REPLICATION_SERVER_MONITOR_OC))
    {
      return new ReplicationServerMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  ReplicationSummaryMonitorEntry.
                       REPLICATION_SUMMARY_MONITOR_OC))
    {
      return new ReplicationSummaryMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  ResultCodeMonitorEntry.RESULT_CODE_MONITOR_OC))
    {
      return new ResultCodeMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  StackTraceMonitorEntry.STACK_TRACE_MONITOR_OC))
    {
      return new StackTraceMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  SystemInfoMonitorEntry.SYSTEM_INFO_MONITOR_OC))
    {
      return new SystemInfoMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  TraditionalWorkQueueMonitorEntry.
                       TRADITIONAL_WORK_QUEUE_MONITOR_OC))
    {
      return new TraditionalWorkQueueMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  UnboundIDWorkQueueMonitorEntry.
                       UNBOUNDID_WORK_QUEUE_MONITOR_OC))
    {
      return new UnboundIDWorkQueueMonitorEntry(entry);
    }
    else if (monitorClass.equalsIgnoreCase(
                  VersionMonitorEntry.VERSION_MONITOR_OC))
    {
      return new VersionMonitorEntry(entry);
    }

    return new MonitorEntry(entry);
  }



  /**
   * Gets the most appropriate monitor class from the provided entry.
   *
   * @param  entry  The entry from which to extract the monitor class.
   *
   * @return  The most appropriate monitor class from the provided entry, or the
   *          generic monitor object class if no appropriate subclass could be
   *          identified.
   */
  @NotNull()
  private static String getMonitorClass(@NotNull final Entry entry)
  {
    String monitorOC = null;
    final String[] ocNames = entry.getObjectClassValues();
    for (final String oc : ocNames)
    {
      if (oc.equalsIgnoreCase("top") ||
          oc.equalsIgnoreCase("extensibleObject") ||
          oc.equalsIgnoreCase(GENERIC_MONITOR_OC))
      {
        // This isn't the class we're looking for.
        continue;
      }
      else if (oc.equalsIgnoreCase(
                    NumericGaugeMonitorEntry.NUMERIC_GAUGE_MONITOR_OC) ||
               oc.equalsIgnoreCase(
                    IndicatorGaugeMonitorEntry.INDICATOR_GAUGE_MONITOR_OC))
      {
        // These classes are subclasses of the base gauge monitor class.
        // We'll allow them even if the monitor class is already set.
        monitorOC = oc;
      }
      else if (oc.equalsIgnoreCase(GaugeMonitorEntry.GAUGE_MONITOR_OC))
      {
        // This is a superclass for the numeric and indicator gauge classes.
        // We'll use it only if the monitor class isn't set, but we won't
        // complain if the monitor class is already set.
        if (monitorOC == null)
        {
          monitorOC = oc;
        }
      }
      else
      {
        if (monitorOC != null)
        {
          if (Debug.debugEnabled(DebugType.MONITOR))
          {
            Debug.debugMonitor(entry,
                 "Multiple monitor subclasses detected:  " + monitorOC +
                      " and " + oc);
          }
        }

        monitorOC = oc;
      }
    }

    if (monitorOC == null)
    {
      if (entry.hasObjectClass(GENERIC_MONITOR_OC))
      {
        Debug.debugMonitor(entry, "No appropriate monitor subclass");
      }
      else
      {
        Debug.debugMonitor(entry, "Missing the generic monitor class");
      }

      return GENERIC_MONITOR_OC;
    }
    else
    {
      return monitorOC;
    }
  }



  /**
   * Retrieves the value of the specified attribute as a {@code Boolean} object.
   *
   * @param  attributeName  The name of the target attribute.
   *
   * @return  The {@code Boolean} object parsed from the specified attribute, or
   *          {@code null} if the attribute does not exist in the entry or it
   *          cannot be parsed as a {@code Boolean} value.
   */
  @Nullable()
  protected final Boolean getBoolean(@NotNull final String attributeName)
  {
    final String valueStr = entry.getAttributeValue(attributeName);
    if (valueStr == null)
    {
      if (Debug.debugEnabled(DebugType.MONITOR))
      {
        Debug.debugMonitor(entry, "No value for Boolean attribute " +
             attributeName);
      }

      return null;
    }
    else if (valueStr.equalsIgnoreCase("true"))
    {
      return Boolean.TRUE;
    }
    else if (valueStr.equalsIgnoreCase("false"))
    {
      return Boolean.FALSE;
    }
    else
    {
      if (Debug.debugEnabled(DebugType.MONITOR))
      {
        Debug.debugMonitor(entry,
             "Invalid value '" + valueStr + "' for Boolean attribute " +
                  attributeName);
      }

      return null;
    }
  }



  /**
   * Retrieves the value of the specified attribute as a {@code Date} object.
   *
   * @param  attributeName  The name of the target attribute.
   *
   * @return  The {@code Date} object parsed from the specified attribute, or
   *          {@code null} if the attribute does not exist in the entry or it
   *          cannot be parsed as a {@code Date} value.
   */
  @Nullable()
  protected final Date getDate(@NotNull final String attributeName)
  {
    final String valueStr = entry.getAttributeValue(attributeName);
    if (valueStr == null)
    {
      if (Debug.debugEnabled(DebugType.MONITOR))
      {
        Debug.debugMonitor(entry, "No value for Date attribute " +
             attributeName);
      }

      return null;
    }
    else
    {
      try
      {
        return StaticUtils.decodeGeneralizedTime(valueStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (Debug.debugEnabled(DebugType.MONITOR))
        {
          Debug.debugMonitor(entry,
               "Invalid value '" + valueStr + "' for Date attribute " +
                    attributeName);
        }

        return null;
      }
    }
  }



  /**
   * Retrieves the value of the specified attribute as a {@code Double} object.
   *
   * @param  attributeName  The name of the target attribute.
   *
   * @return  The {@code Double} object parsed from the specified attribute, or
   *          {@code null} if the attribute does not exist in the entry or it
   *          cannot be parsed as a {@code Double} value.
   */
  @Nullable()
  protected final Double getDouble(@NotNull final String attributeName)
  {
    final String valueStr = entry.getAttributeValue(attributeName);
    if (valueStr == null)
    {
      if (Debug.debugEnabled(DebugType.MONITOR))
      {
        Debug.debugMonitor(entry, "No value for Double attribute " +
             attributeName);
      }

      return null;
    }
    else
    {
      try
      {
        return Double.parseDouble(valueStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (Debug.debugEnabled(DebugType.MONITOR))
        {
          Debug.debugMonitor(entry,
               "Invalid value '" + valueStr + "' for Double attribute " +
                    attributeName);
        }

        return null;
      }
    }
  }



  /**
   * Retrieves the value of the specified attribute as an {@code Integer}
   * object.
   *
   * @param  attributeName  The name of the target attribute.
   *
   * @return  The {@code Integer} object parsed from the specified attribute, or
   *          {@code null} if the attribute does not exist in the entry or it
   *          cannot be parsed as an {@code Integer} value.
   */
  @Nullable()
  protected final Integer getInteger(@NotNull final String attributeName)
  {
    final String valueStr = entry.getAttributeValue(attributeName);
    if (valueStr == null)
    {
      if (Debug.debugEnabled(DebugType.MONITOR))
      {
        Debug.debugMonitor(entry, "No value for Integer attribute " +
             attributeName);
      }

      return null;
    }
    else
    {
      try
      {
        return Integer.parseInt(valueStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (Debug.debugEnabled(DebugType.MONITOR))
        {
          Debug.debugMonitor(entry,
               "Invalid value '" + valueStr + "' for Integer attribute " +
                    attributeName);
        }

        return null;
      }
    }
  }



  /**
   * Retrieves the value of the specified attribute as a {@code Long} object.
   *
   * @param  attributeName  The name of the target attribute.
   *
   * @return  The {@code Long} object parsed from the specified attribute, or
   *          {@code null} if the attribute does not exist in the entry or it
   *          cannot be parsed as a {@code Long} value.
   */
  @Nullable()
  protected final Long getLong(@NotNull final String attributeName)
  {
    final String valueStr = entry.getAttributeValue(attributeName);
    if (valueStr == null)
    {
      if (Debug.debugEnabled(DebugType.MONITOR))
      {
        Debug.debugMonitor(entry,
             "No value for Long attribute " + attributeName);
      }

      return null;
    }
    else
    {
      try
      {
        return Long.parseLong(valueStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (Debug.debugEnabled(DebugType.MONITOR))
        {
          Debug.debugMonitor(entry,
               "Invalid value '" + valueStr + "' for Long attribute " +
                    attributeName);
        }

        return null;
      }
    }
  }



  /**
   * Retrieves the value of the specified attribute as a string.
   *
   * @param  attributeName  The name of the target attribute.
   *
   * @return  The string value of the specified attribute, or {@code null} if it
   *          does not exist in the entry.
   */
  @Nullable()
  protected final String getString(@NotNull final String attributeName)
  {
    final String valueStr = entry.getAttributeValue(attributeName);
    if ((valueStr == null) && Debug.debugEnabled(DebugType.MONITOR))
    {
      Debug.debugMonitor(entry,
           "No value for string attribute " + attributeName);
    }

    return valueStr;
  }



  /**
   * Retrieves the set of values of the specified attribute as a string list.
   *
   * @param  attributeName  The name of the target attribute.
   *
   * @return  The string values of the specified attribute, or an empty list if
   *          the specified attribute does not exist in the entry.
   */
  @NotNull()
  protected final List<String> getStrings(@NotNull final String attributeName)
  {
    final String[] valueStrs = entry.getAttributeValues(attributeName);
    if (valueStrs == null)
    {
      if (Debug.debugEnabled(DebugType.MONITOR))
      {
        Debug.debugMonitor(entry,
             "No values for string attribute " + attributeName);
      }

      return Collections.emptyList();
    }

    return Collections.unmodifiableList(Arrays.asList(valueStrs));
  }



  /**
   * Adds a new monitor attribute to the specified map using the provided
   * information.
   *
   * @param  attrs        The attribute map to which the information should be
   *                      added.
   * @param  name         The name to use for this monitor attribute.  It must
   *                      be unique among all other monitor attribute names for
   *                      the associated monitor entry.
   * @param  displayName  The human-readable display name for the monitor
   *                      attribute.
   * @param  description  The human-readable description for the monitor
   *                      attribute.
   * @param  value        The value for the monitor attribute.
   */
  protected static void addMonitorAttribute(
                 @NotNull final Map<String,MonitorAttribute> attrs,
                 @NotNull final String name,
                 @NotNull final String displayName,
                 @Nullable final String description,
                 @NotNull final Boolean value)
  {
    final String lowerName = StaticUtils.toLowerCase(name);

    final MonitorAttribute a =
         new MonitorAttribute(lowerName, displayName, description, value);
    attrs.put(lowerName, a);
  }



  /**
   * Adds a new monitor attribute to the specified map using the provided
   * information.
   *
   * @param  attrs        The attribute map to which the information should be
   *                      added.
   * @param  name         The name to use for this monitor attribute.  It must
   *                      be unique among all other monitor attribute names for
   *                      the associated monitor entry.
   * @param  displayName  The human-readable display name for the monitor
   *                      attribute.
   * @param  description  The human-readable description for the monitor
   *                      attribute.
   * @param  value        The value for the monitor attribute.
   */
  protected static void addMonitorAttribute(
                 @NotNull final Map<String,MonitorAttribute> attrs,
                 @NotNull final String name,
                 @NotNull final String displayName,
                 @Nullable final String description,
                 @NotNull final Date value)
  {
    final String lowerName = StaticUtils.toLowerCase(name);

    final MonitorAttribute a =
         new MonitorAttribute(lowerName, displayName, description, value);
    attrs.put(lowerName, a);
  }



  /**
   * Adds a new monitor attribute to the specified map using the provided
   * information.
   *
   * @param  attrs        The attribute map to which the information should be
   *                      added.
   * @param  name         The name to use for this monitor attribute.  It must
   *                      be unique among all other monitor attribute names for
   *                      the associated monitor entry.
   * @param  displayName  The human-readable display name for the monitor
   *                      attribute.
   * @param  description  The human-readable description for the monitor
   *                      attribute.
   * @param  value        The value for the monitor attribute.
   */
  protected static void addMonitorAttribute(
                 @NotNull final Map<String,MonitorAttribute> attrs,
                 @NotNull final String name,
                 @NotNull final String displayName,
                 @Nullable final String description,
                 @NotNull final Double value)
  {
    final String lowerName = StaticUtils.toLowerCase(name);

    final MonitorAttribute a =
         new MonitorAttribute(lowerName, displayName, description, value);
    attrs.put(lowerName, a);
  }



  /**
   * Adds a new monitor attribute to the specified map using the provided
   * information.
   *
   * @param  attrs        The attribute map to which the information should be
   *                      added.
   * @param  name         The name to use for this monitor attribute.  It must
   *                      be unique among all other monitor attribute names for
   *                      the associated monitor entry.
   * @param  displayName  The human-readable display name for the monitor
   *                      attribute.
   * @param  description  The human-readable description for the monitor
   *                      attribute.
   * @param  value        The value for the monitor attribute.
   */
  protected static void addMonitorAttribute(
                 @NotNull final Map<String,MonitorAttribute> attrs,
                 @NotNull final String name,
                 @NotNull final String displayName,
                 @Nullable final String description,
                 @NotNull final Integer value)
  {
    final String lowerName = StaticUtils.toLowerCase(name);

    final MonitorAttribute a =
         new MonitorAttribute(lowerName, displayName, description, value);
    attrs.put(lowerName, a);
  }



  /**
   * Adds a new monitor attribute to the specified map using the provided
   * information.
   *
   * @param  attrs        The attribute map to which the information should be
   *                      added.
   * @param  name         The name to use for this monitor attribute.  It must
   *                      be unique among all other monitor attribute names for
   *                      the associated monitor entry.
   * @param  displayName  The human-readable display name for the monitor
   *                      attribute.
   * @param  description  The human-readable description for the monitor
   *                      attribute.
   * @param  value        The value for the monitor attribute.
   */
  protected static void addMonitorAttribute(
                 @NotNull final Map<String,MonitorAttribute> attrs,
                 @NotNull final String name,
                 @NotNull final String displayName,
                 @Nullable final String description,
                 @NotNull final Long value)
  {
    final String lowerName = StaticUtils.toLowerCase(name);

    final MonitorAttribute a =
         new MonitorAttribute(lowerName, displayName, description, value);
    attrs.put(lowerName, a);
  }



  /**
   * Adds a new monitor attribute to the specified map using the provided
   * information.
   *
   * @param  attrs        The attribute map to which the information should be
   *                      added.
   * @param  name         The name to use for this monitor attribute.  It must
   *                      be unique among all other monitor attribute names for
   *                      the associated monitor entry.
   * @param  displayName  The human-readable display name for the monitor
   *                      attribute.
   * @param  description  The human-readable description for the monitor
   *                      attribute.
   * @param  value        The value for the monitor attribute.
   */
  protected static void addMonitorAttribute(
                 @NotNull final Map<String,MonitorAttribute> attrs,
                 @NotNull final String name,
                 @NotNull final String displayName,
                 @Nullable final String description,
                 @NotNull final String value)
  {
    final String lowerName = StaticUtils.toLowerCase(name);

    final MonitorAttribute a =
         new MonitorAttribute(lowerName, displayName, description, value);
    attrs.put(lowerName, a);
  }



  /**
   * Adds a new monitor attribute to the specified map using the provided
   * information.
   *
   * @param  attrs        The attribute map to which the information should be
   *                      added.
   * @param  name         The name to use for this monitor attribute.  It must
   *                      be unique among all other monitor attribute names for
   *                      the associated monitor entry.
   * @param  displayName  The human-readable display name for the monitor
   *                      attribute.
   * @param  description  The human-readable description for the monitor
   *                      attribute.
   * @param  values       The set of values for the monitor attribute.
   */
  protected static void addMonitorAttribute(
                 @NotNull final Map<String,MonitorAttribute> attrs,
                 @NotNull final String name,
                 @NotNull final String displayName,
                 @Nullable final String description,
                 @NotNull final List<String> values)
  {
    final String lowerName = StaticUtils.toLowerCase(name);

    final MonitorAttribute a =
         new MonitorAttribute(lowerName, displayName, description,
                              values.toArray(new String[values.size()]));
    attrs.put(lowerName, a);
  }



  /**
   * Retrieves a string representation of this monitor entry.
   *
   * @return  A string representation of this monitor entry.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this monitor entry to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public final void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("MonitorEntry(dn='");
    buffer.append(entry.getDN());
    buffer.append("', monitorClass='");
    buffer.append(monitorClass);
    buffer.append('\'');

    final Iterator<MonitorAttribute> iterator =
         getMonitorAttributes().values().iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next());
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append(')');
  }
}
