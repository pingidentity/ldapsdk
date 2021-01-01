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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the
 * processing times of operations that are performed in the server.  It includes
 * the total counts of each type of operation, the average response time for
 * each type of operation, and counts and percentages of operations whose
 * server-side processing time fits in defined buckets.
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
 * The following buckets are defined in the default configuration:
 * <UL>
 *   <LI>Less than 1ms.</LI>
 *   <LI>Greater than or equal to 1ms and less than 2ms.</LI>
 *   <LI>Greater than or equal to 2ms and less than 3ms.</LI>
 *   <LI>Greater than or equal to 3ms and less than 5ms.</LI>
 *   <LI>Greater than or equal to 5ms and less than 10ms.</LI>
 *   <LI>Greater than or equal to 10ms and less than 20ms.</LI>
 *   <LI>Greater than or equal to 20ms and less than 30ms.</LI>
 *   <LI>Greater than or equal to 30ms and less than 50ms.</LI>
 *   <LI>Greater than or equal to 50ms and less than 100ms.</LI>
 *   <LI>Greater than or equal to 100ms and less than 1000ms.</LI>
 *   <LI>Greater than or equal to 1000ms.</LI>
 * </UL>
 * It provides the following information for each operation, as well as for the
 * total for all operations:
 * <UL>
 *   <LI>The number of operations of the specified type within each bucket.</LI>
 *   <LI>The percentage of operations of the specified type within each
 *       bucket.</LI>
 *   <LI>The aggregate percentage of operations of the specified type for each
 *        bucket (i.e., the percentage of operations in that bucket or any
 *        bucket for a lower duration).</LI>
 * </UL>
 * The server should present at most one processing time histogram monitor
 * entry.  It can be retrieved using the
 * {@link MonitorManager#getProcessingTimeHistogramMonitorEntry} method.
 * This entry provides specific methods for accessing information about
 * processing times per bucket (e.g., the
 * {@link ProcessingTimeHistogramMonitorEntry#getAllOpsPercent} method can be
 * used to retrieve a map containing the percent of operations within each
 * bucket).  Alternately, this information may be accessed using the generic
 * API.  See the {@link MonitorManager} class documentation for an example that
 * demonstrates the use of the generic API for accessing monitor data.
 */
@NotMutable()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class ProcessingTimeHistogramMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in processing time histogram monitor
   * entries.
   */
  @NotNull static final String PROCESSING_TIME_HISTOGRAM_MONITOR_OC =
       "ds-processing-time-histogram-monitor-entry";



  /**
   * The name of the attribute that contains the total number of add
   * operations performed in the server.
   */
  @NotNull private static final String ATTR_ADD_TOTAL_COUNT =
       "addOpsTotalCount";



  /**
   * The name of the attribute that contains the average response time in
   * milliseconds for add operations performed in the server.
   */
  @NotNull private static final String ATTR_ADD_AVERAGE_RESPONSE_TIME_MS =
       "addOpsAverageResponseTimeMillis";



  /**
   * The name of the attribute that contains the aggregate percentage of add
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_ADD_AGGREGATE_PERCENT =
       "addOpsAggregatePercent";



  /**
   * The name of the attribute that contains the total number of add operations
   * within each processing time bucket.
   */
  @NotNull private static final String ATTR_ADD_COUNT = "addOpsCount";



  /**
   * The name of the attribute that contains the percentage of add operations
   * within each processing time bucket.
   */
  @NotNull private static final String ATTR_ADD_PERCENT = "addOpsPercent";



  /**
   * The name of the attribute that contains the total number of all
   * operations performed in the server.
   */
  @NotNull private static final String ATTR_ALL_TOTAL_COUNT =
       "allOpsTotalCount";



  /**
   * The name of the attribute that contains the average response time in
   * milliseconds for all operations performed in the server.
   */
  @NotNull private static final String ATTR_ALL_AVERAGE_RESPONSE_TIME_MS =
       "allOpsAverageResponseTimeMillis";



  /**
   * The name of the attribute that contains the aggregate percentage of
   * operations of all types within each processing time bucket.
   */
  @NotNull private static final String ATTR_ALL_AGGREGATE_PERCENT =
       "allOpsAggregatePercent";



  /**
   * The name of the attribute that contains the total number of operations of
   * all types within each processing time bucket.
   */
  @NotNull private static final String ATTR_ALL_COUNT = "allOpsCount";



  /**
   * The name of the attribute that contains the percentage of operations of all
   * types within each processing time bucket.
   */
  @NotNull private static final String ATTR_ALL_PERCENT = "allOpsPercent";



  /**
   * The name of the attribute that contains the total number of bind
   * operations performed in the server.
   */
  @NotNull private static final String ATTR_BIND_TOTAL_COUNT =
       "bindOpsTotalCount";



  /**
   * The name of the attribute that contains the average response time in
   * milliseconds for bind operations performed in the server.
   */
  @NotNull private static final String ATTR_BIND_AVERAGE_RESPONSE_TIME_MS =
       "bindOpsAverageResponseTimeMillis";



  /**
   * The name of the attribute that contains the aggregate percentage of bind
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_BIND_AGGREGATE_PERCENT =
       "bindOpsAggregatePercent";



  /**
   * The name of the attribute that contains the total number of bind operations
   * within each processing time bucket.
   */
  @NotNull private static final String ATTR_BIND_COUNT = "bindOpsCount";



  /**
   * The name of the attribute that contains the percentage of bind operations
   * within each processing time bucket.
   */
  @NotNull private static final String ATTR_BIND_PERCENT = "bindOpsPercent";



  /**
   * The name of the attribute that contains the total number of compare
   * operations performed in the server.
   */
  @NotNull private static final String ATTR_COMPARE_TOTAL_COUNT =
       "compareOpsTotalCount";



  /**
   * The name of the attribute that contains the average response time in
   * milliseconds for compare operations performed in the server.
   */
  @NotNull private static final String ATTR_COMPARE_AVERAGE_RESPONSE_TIME_MS =
       "compareOpsAverageResponseTimeMillis";



  /**
   * The name of the attribute that contains the aggregate percentage of compare
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_COMPARE_AGGREGATE_PERCENT =
       "compareOpsAggregatePercent";



  /**
   * The name of the attribute that contains the total number of compare
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_COMPARE_COUNT = "compareOpsCount";



  /**
   * The name of the attribute that contains the percentage of compare
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_COMPARE_PERCENT =
       "compareOpsPercent";



  /**
   * The name of the attribute that contains the total number of delete
   * operations performed in the server.
   */
  @NotNull private static final String ATTR_DELETE_TOTAL_COUNT =
       "deleteOpsTotalCount";



  /**
   * The name of the attribute that contains the average response time in
   * milliseconds for delete operations performed in the server.
   */
  @NotNull private static final String ATTR_DELETE_AVERAGE_RESPONSE_TIME_MS =
       "deleteOpsAverageResponseTimeMillis";



  /**
   * The name of the attribute that contains the aggregate percentage of delete
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_DELETE_AGGREGATE_PERCENT =
       "deleteOpsAggregatePercent";



  /**
   * The name of the attribute that contains the total number of delete
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_DELETE_COUNT = "deleteOpsCount";



  /**
   * The name of the attribute that contains the percentage of delete operations
   * within each processing time bucket.
   */
  @NotNull private static final String ATTR_DELETE_PERCENT =
       "deleteOpsPercent";



  /**
   * The name of the attribute that contains the total number of extended
   * operations performed in the server.
   */
  @NotNull private static final String ATTR_EXTENDED_TOTAL_COUNT =
       "extendedOpsTotalCount";



  /**
   * The name of the attribute that contains the average response time in
   * milliseconds for extended operations performed in the server.
   */
  @NotNull private static final String ATTR_EXTENDED_AVERAGE_RESPONSE_TIME_MS =
       "extendedOpsAverageResponseTimeMillis";



  /**
   * The name of the attribute that contains the aggregate percentage of
   * extended operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_EXTENDED_AGGREGATE_PERCENT =
       "extendedOpsAggregatePercent";



  /**
   * The name of the attribute that contains the total number of extended
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_EXTENDED_COUNT = "extendedOpsCount";



  /**
   * The name of the attribute that contains the percentage of extended
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_EXTENDED_PERCENT =
       "extendedOpsPercent";



  /**
   * The name of the attribute that contains the total number of modify
   * operations performed in the server.
   */
  @NotNull private static final String ATTR_MODIFY_TOTAL_COUNT =
       "modifyOpsTotalCount";



  /**
   * The name of the attribute that contains the average response time in
   * milliseconds for modify operations performed in the server.
   */
  @NotNull private static final String ATTR_MODIFY_AVERAGE_RESPONSE_TIME_MS =
       "modifyOpsAverageResponseTimeMillis";



  /**
   * The name of the attribute that contains the aggregate percentage of modify
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_MODIFY_AGGREGATE_PERCENT =
       "modifyOpsAggregatePercent";



  /**
   * The name of the attribute that contains the total number of modify
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_MODIFY_COUNT = "modifyOpsCount";



  /**
   * The name of the attribute that contains the percentage of modify operations
   * within each processing time bucket.
   */
  @NotNull private static final String ATTR_MODIFY_PERCENT = "modifyOpsPercent";



  /**
   * The name of the attribute that contains the total number of modify DN
   * operations performed in the server.
   */
  @NotNull private static final String ATTR_MODIFY_DN_TOTAL_COUNT =
       "modifyDNOpsTotalCount";



  /**
   * The name of the attribute that contains the average response time in
   * milliseconds for modify DN operations performed in the server.
   */
  @NotNull private static final String ATTR_MODIFY_DN_AVERAGE_RESPONSE_TIME_MS =
       "modifyDNOpsAverageResponseTimeMillis";



  /**
   * The name of the attribute that contains the aggregate percentage of modify
   * DN operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_MODIFY_DN_AGGREGATE_PERCENT =
       "modifyDNOpsAggregatePercent";



  /**
   * The name of the attribute that contains the total number of modify DN
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_MODIFY_DN_COUNT =
       "modifyDNOpsCount";



  /**
   * The name of the attribute that contains the percentage of modify DN
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_MODIFY_DN_PERCENT =
       "modifyDNOpsPercent";



  /**
   * The name of the attribute that contains the total number of search
   * operations performed in the server.
   */
  @NotNull private static final String ATTR_SEARCH_TOTAL_COUNT =
       "searchOpsTotalCount";



  /**
   * The name of the attribute that contains the average response time in
   * milliseconds for search operations performed in the server.
   */
  @NotNull private static final String ATTR_SEARCH_AVERAGE_RESPONSE_TIME_MS =
       "searchOpsAverageResponseTimeMillis";



  /**
   * The name of the attribute that contains the aggregate percentage of search
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_SEARCH_AGGREGATE_PERCENT =
       "searchOpsAggregatePercent";



  /**
   * The name of the attribute that contains the total number of search
   * operations within each processing time bucket.
   */
  @NotNull private static final String ATTR_SEARCH_COUNT = "searchOpsCount";



  /**
   * The name of the attribute that contains the percentage of search operations
   * within each processing time bucket.
   */
  @NotNull private static final String ATTR_SEARCH_PERCENT = "searchOpsPercent";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2498009928344820276L;



  // The percent of add operations in each bucket.
  @NotNull private final Map<Long,Double> addOpsPercent;

  // The aggregate percent of add operations in each bucket.
  @NotNull private final Map<Long,Double> addOpsAggregatePercent;

  // The percent of operations of all types in each bucket.
  @NotNull private final Map<Long,Double> allOpsPercent;

  // The aggregate percent of operations of all types in each bucket.
  @NotNull private final Map<Long,Double> allOpsAggregatePercent;

  // The percent of bind operations in each bucket.
  @NotNull private final Map<Long,Double> bindOpsPercent;

  // The aggregate percent of bind operations in each bucket.
  @NotNull private final Map<Long,Double> bindOpsAggregatePercent;

  // The percent of compare operations in each bucket.
  @NotNull private final Map<Long,Double> compareOpsPercent;

  // The aggregate percent of compare operations in each bucket.
  @NotNull private final Map<Long,Double> compareOpsAggregatePercent;

  // The percent of delete operations in each bucket.
  @NotNull private final Map<Long,Double> deleteOpsPercent;

  // The aggregate percent of delete operations in each bucket.
  @NotNull private final Map<Long,Double> deleteOpsAggregatePercent;

  // The percent of extended operations in each bucket.
  @NotNull private final Map<Long,Double> extendedOpsPercent;

  // The aggregate percent of extended operations in each bucket.
  @NotNull private final Map<Long,Double> extendedOpsAggregatePercent;

  // The percent of modify operations in each bucket.
  @NotNull private final Map<Long,Double> modifyOpsPercent;

  // The aggregate percent of modify operations in each bucket.
  @NotNull private final Map<Long,Double> modifyOpsAggregatePercent;

  // The percent of modify DN operations in each bucket.
  @NotNull private final Map<Long,Double> modifyDNOpsPercent;

  // The aggregate percent of modify DN operations in each bucket.
  @NotNull private final Map<Long,Double> modifyDNOpsAggregatePercent;

  // The percent of search operations in each bucket.
  @NotNull private final Map<Long,Double> searchOpsPercent;

  // The aggregate percent of search operations in each bucket.
  @NotNull private final Map<Long,Double> searchOpsAggregatePercent;

  // The number of add operations in each bucket.
  @NotNull private final Map<Long,Long> addOpsCount;

  // The number of operations of all types in each bucket.
  @NotNull private final Map<Long,Long> allOpsCount;

  // The number of bind operations in each bucket.
  @NotNull private final Map<Long,Long> bindOpsCount;

  // The number of compare operations in each bucket.
  @NotNull private final Map<Long,Long> compareOpsCount;

  // The number of delete operations in each bucket.
  @NotNull private final Map<Long,Long> deleteOpsCount;

  // The number of extended operations in each bucket.
  @NotNull private final Map<Long,Long> extendedOpsCount;

  // The number of modify operations in each bucket.
  @NotNull private final Map<Long,Long> modifyOpsCount;

  // The number of modifyDN operations in each bucket.
  @NotNull private final Map<Long,Long> modifyDNOpsCount;

  // The number of search operations in each bucket.
  @NotNull private final Map<Long,Long> searchOpsCount;

  // The total number of add operations.
  @Nullable private final Long addOpsTotalCount;

  // The total number of all operations.
  @Nullable private final Long allOpsTotalCount;

  // The total number of bind operations.
  @Nullable private final Long bindOpsTotalCount;

  // The total number of compare operations.
  @Nullable private final Long compareOpsTotalCount;

  // The total number of delete operations.
  @Nullable private final Long deleteOpsTotalCount;

  // The total number of extended operations.
  @Nullable private final Long extendedOpsTotalCount;

  // The total number of modify operations.
  @Nullable private final Long modifyOpsTotalCount;

  // The total number of modify DN operations.
  @Nullable private final Long modifyDNOpsTotalCount;

  // The total number of search operations.
  @Nullable private final Long searchOpsTotalCount;

  // The average response time in milliseconds for add operations.
  @Nullable private final Double addOpsAvgResponseTimeMillis;

  // The average response time in milliseconds for all operations.
  @Nullable private final Double allOpsAvgResponseTimeMillis;

  // The average response time in milliseconds for bind operations.
  @Nullable private final Double bindOpsAvgResponseTimeMillis;

  // The average response time in milliseconds for compare operations.
  @Nullable private final Double compareOpsAvgResponseTimeMillis;

  // The average response time in milliseconds for delete operations.
  @Nullable private final Double deleteOpsAvgResponseTimeMillis;

  // The average response time in milliseconds for extended operations.
  @Nullable private final Double extendedOpsAvgResponseTimeMillis;

  // The average response time in milliseconds for modify operations.
  @Nullable private final Double modifyOpsAvgResponseTimeMillis;

  // The average response time in milliseconds for modify DN operations.
  @Nullable private final Double modifyDNOpsAvgResponseTimeMillis;

  // The average response time in milliseconds for search operations.
  @Nullable private final Double searchOpsAvgResponseTimeMillis;


  /**
   * Creates a new processing time histogram monitor entry from the provided
   * entry.
   *
   * @param  entry  The entry to be parsed as a processing time histogram
   *                monitor entry.  It must not be {@code null}.
   */
  public ProcessingTimeHistogramMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    allOpsTotalCount = getLong(ATTR_ALL_TOTAL_COUNT);
    allOpsAvgResponseTimeMillis = getDouble(ATTR_ALL_AVERAGE_RESPONSE_TIME_MS);
    allOpsCount = parseCountAttribute(entry, ATTR_ALL_COUNT);
    allOpsPercent = parsePercentAttribute(entry, ATTR_ALL_PERCENT);
    allOpsAggregatePercent =
         parsePercentAttribute(entry, ATTR_ALL_AGGREGATE_PERCENT);

    addOpsTotalCount = getLong(ATTR_ADD_TOTAL_COUNT);
    addOpsAvgResponseTimeMillis = getDouble(ATTR_ADD_AVERAGE_RESPONSE_TIME_MS);
    addOpsCount = parseCountAttribute(entry, ATTR_ADD_COUNT);
    addOpsPercent = parsePercentAttribute(entry, ATTR_ADD_PERCENT);
    addOpsAggregatePercent =
         parsePercentAttribute(entry, ATTR_ADD_AGGREGATE_PERCENT);

    bindOpsTotalCount = getLong(ATTR_BIND_TOTAL_COUNT);
    bindOpsAvgResponseTimeMillis =
         getDouble(ATTR_BIND_AVERAGE_RESPONSE_TIME_MS);
    bindOpsCount = parseCountAttribute(entry, ATTR_BIND_COUNT);
    bindOpsPercent = parsePercentAttribute(entry, ATTR_BIND_PERCENT);
    bindOpsAggregatePercent =
         parsePercentAttribute(entry, ATTR_BIND_AGGREGATE_PERCENT);

    compareOpsTotalCount = getLong(ATTR_COMPARE_TOTAL_COUNT);
    compareOpsAvgResponseTimeMillis =
         getDouble(ATTR_COMPARE_AVERAGE_RESPONSE_TIME_MS);
    compareOpsCount = parseCountAttribute(entry, ATTR_COMPARE_COUNT);
    compareOpsPercent = parsePercentAttribute(entry, ATTR_COMPARE_PERCENT);
    compareOpsAggregatePercent =
         parsePercentAttribute(entry, ATTR_COMPARE_AGGREGATE_PERCENT);

    deleteOpsTotalCount = getLong(ATTR_DELETE_TOTAL_COUNT);
    deleteOpsAvgResponseTimeMillis =
         getDouble(ATTR_DELETE_AVERAGE_RESPONSE_TIME_MS);
    deleteOpsCount = parseCountAttribute(entry, ATTR_DELETE_COUNT);
    deleteOpsPercent = parsePercentAttribute(entry, ATTR_DELETE_PERCENT);
    deleteOpsAggregatePercent =
         parsePercentAttribute(entry, ATTR_DELETE_AGGREGATE_PERCENT);

    extendedOpsTotalCount = getLong(ATTR_EXTENDED_TOTAL_COUNT);
    extendedOpsAvgResponseTimeMillis =
         getDouble(ATTR_EXTENDED_AVERAGE_RESPONSE_TIME_MS);
    extendedOpsCount = parseCountAttribute(entry, ATTR_EXTENDED_COUNT);
    extendedOpsPercent = parsePercentAttribute(entry, ATTR_EXTENDED_PERCENT);
    extendedOpsAggregatePercent =
         parsePercentAttribute(entry, ATTR_EXTENDED_AGGREGATE_PERCENT);

    modifyOpsTotalCount = getLong(ATTR_MODIFY_TOTAL_COUNT);
    modifyOpsAvgResponseTimeMillis =
         getDouble(ATTR_MODIFY_AVERAGE_RESPONSE_TIME_MS);
    modifyOpsCount = parseCountAttribute(entry, ATTR_MODIFY_COUNT);
    modifyOpsPercent = parsePercentAttribute(entry, ATTR_MODIFY_PERCENT);
    modifyOpsAggregatePercent =
         parsePercentAttribute(entry, ATTR_MODIFY_AGGREGATE_PERCENT);

    modifyDNOpsTotalCount = getLong(ATTR_MODIFY_DN_TOTAL_COUNT);
    modifyDNOpsAvgResponseTimeMillis =
         getDouble(ATTR_MODIFY_DN_AVERAGE_RESPONSE_TIME_MS);
    modifyDNOpsCount = parseCountAttribute(entry, ATTR_MODIFY_DN_COUNT);
    modifyDNOpsPercent = parsePercentAttribute(entry, ATTR_MODIFY_DN_PERCENT);
    modifyDNOpsAggregatePercent =
         parsePercentAttribute(entry, ATTR_MODIFY_DN_AGGREGATE_PERCENT);

    searchOpsTotalCount = getLong(ATTR_SEARCH_TOTAL_COUNT);
    searchOpsAvgResponseTimeMillis =
         getDouble(ATTR_SEARCH_AVERAGE_RESPONSE_TIME_MS);
    searchOpsCount = parseCountAttribute(entry, ATTR_SEARCH_COUNT);
    searchOpsPercent = parsePercentAttribute(entry, ATTR_SEARCH_PERCENT);
    searchOpsAggregatePercent =
         parsePercentAttribute(entry, ATTR_SEARCH_AGGREGATE_PERCENT);
  }



  /**
   * Parses the value of a specified attribute to obtain a mapping between the
   * lower bucket boundary and an integer value.
   *
   * @param  entry  The entry containing the data to process.
   * @param  name   The name of the attribute containing the data to process.
   *
   * @return  A map with the parsed information, or an empty map if the
   *          specified attribute did not exist or could not be parsed.
   */
  @NotNull()
  private static Map<Long,Long> parseCountAttribute(@NotNull final Entry entry,
                                                    @NotNull final String name)
  {
    final String[] values = entry.getAttributeValues(name);
    if ((values == null) || (values.length == 0))
    {
      return Collections.emptyMap();
    }

    try
    {
      final LinkedHashMap<Long,Long> map =
           new LinkedHashMap<>(StaticUtils.computeMapCapacity(50));

      // FIXME -- Do we need to figure out how to make this
      // internationalizeable?

      // The lower bound for the first bucket will always be zero, so just look
      // for the colon to separate the label from the value.
      int colonPos = values[0].indexOf(':');
      map.put(0L, Long.parseLong(values[0].substring(colonPos+1).trim()));

      // For remaining values, the lower bound will be the number immediately
      // after "Between " and immediately before "ms".
      for (int i=1; i < values.length; i++)
      {
        final long lowerBound;
        int msPos = values[i].indexOf("ms ");
        if (msPos < 0)
        {
          // This must be the last value.
          msPos = values[i].indexOf("ms:");
          lowerBound = Long.parseLong(values[i].substring(9, msPos));
        }
        else
        {
          lowerBound = Long.parseLong(values[i].substring(8, msPos));
        }

        colonPos = values[i].indexOf(':', msPos);
        map.put(lowerBound,
                Long.parseLong(values[i].substring(colonPos+1).trim()));
      }

      return Collections.unmodifiableMap(map);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return Collections.emptyMap();
    }
  }



  /**
   * Parses the value of a specified attribute to obtain a mapping between the
   * lower bucket boundary and a floating-point value.
   *
   * @param  entry  The entry containing the data to process.
   * @param  name   The name of the attribute containing the data to process.
   *
   * @return  A map with the parsed information, or an empty map if the
   *          specified attribute did not exist or could not be parsed.
   */
  @NotNull()
  private static Map<Long,Double> parsePercentAttribute(
               @NotNull final Entry entry,
               @NotNull final String name)
  {
    final String[] values = entry.getAttributeValues(name);
    if ((values == null) || (values.length == 0))
    {
      return Collections.emptyMap();
    }

    try
    {
      final LinkedHashMap<Long,Double> map =
           new LinkedHashMap<>(StaticUtils.computeMapCapacity(50));

      // FIXME -- Do we need to figure out how to make this
      // internationalizeable?

      // The standard percent histogram attributes will always use the following
      // pattern:
      // - One "Less than Xms: N.NNNN%" line.
      // - Zero or more "Between Xms and Yms: N.NNNN%" lines.
      // - One "At least Xms: N.NNNN%" line.
      //
      // The aggregate percent histogram attributes may use the above pattern,
      // or they may instead use the following alternate pattern (which will
      // have one less value because the last aggregate percent is known to be
      // 100% and will be implied rather than explicitly stated):
      // - One or more "Less than Xms: N.NNNN%" lines.
      //
      // We need to support both formats.
      boolean atLeastFound = false;
      long lastUpperBound = 0L;
      for (final String s : values)
      {
        final int colonPos = s.indexOf(':');
        final int pctPos = s.indexOf('%', colonPos);
        final double percent =
             Double.parseDouble(s.substring(colonPos+1, pctPos));

        final int msPos = s.indexOf("ms");
        if (s.startsWith("Less than "))
        {
          map.put(lastUpperBound, percent);
          lastUpperBound = Long.parseLong(s.substring(10, msPos));
        }
        else if (s.startsWith("Between "))
        {
          final long lowerBound = Long.parseLong(s.substring(8, msPos));
          map.put(lowerBound, percent);

          final int secondMSPos =  s.indexOf("ms:", msPos+1);
          lastUpperBound = Long.parseLong(s.substring(msPos+7, secondMSPos));
        }
        else
        {
          atLeastFound = true;
          final long lowerBound = Long.parseLong(s.substring(9, msPos));
          map.put(lowerBound, percent);
        }
      }

      if (! atLeastFound)
      {
        map.put(lastUpperBound, 100.0d);
      }

      return Collections.unmodifiableMap(map);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return Collections.emptyMap();
    }
  }



  /**
   * Retrieves the total number of operations that have been performed in the
   * server.
   *
   * @return  The total number of operations that have been performed in the
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public final Long getAllOpsTotalCount()
  {
    return allOpsTotalCount;
  }



  /**
   * Retrieves the average response time in milliseconds of all operations
   * of all types performed in the server.
   *
   * @return  The average response time in milliseconds of all operations of all
   *          types performed in the server, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public final Double getAllOpsAverageResponseTimeMillis()
  {
    return allOpsAvgResponseTimeMillis;
  }



  /**
   * Retrieves a map with information about the total number of operations of
   * all types within each of the response time buckets.  The mapping will be
   * between the lower bound for the processing time bucket in milliseconds and
   * the number of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the total number of operations of all
   *          types within each of the response time buckets, or an empty map if
   *          it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Long> getAllOpsCount()
  {
    return allOpsCount;
  }



  /**
   * Retrieves a map with information about the percentage of operations of
   * all types within each of the response time buckets.  The mapping will be
   * between the lower bound for the processing time bucket in milliseconds and
   * the percentage of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the percentage of operations of all
   *          types within each of the response time buckets, or an empty map if
   *          it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getAllOpsPercent()
  {
    return allOpsPercent;
  }



  /**
   * Retrieves a map with information about the aggregate percentage of
   * operations of all types within each of the response time buckets or one of
   * the lower response time buckets.  The mapping will be between the lower
   * bound for the processing time bucket in milliseconds and the aggregate
   * percentage of operations whose processing time fell within that or lower
   * response time buckets.
   *
   * @return  A map with information about the aggregate percentage of
   *          operations of all types within each of the response time buckets,
   *          or an empty map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getAllOpsAggregatePercent()
  {
    return allOpsAggregatePercent;
  }



  /**
   * Retrieves the total number of add operations that have been performed
   * in the server.
   *
   * @return  The total number of add operations that have been performed in the
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public final Long getAddOpsTotalCount()
  {
    return addOpsTotalCount;
  }



  /**
   * Retrieves the average response time in milliseconds of add operations
   * performed in the server.
   *
   * @return  The average response time in milliseconds of add operations
   *          that have been performed in the server, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public final Double getAddOpsAverageResponseTimeMillis()
  {
    return addOpsAvgResponseTimeMillis;
  }



  /**
   * Retrieves a map with information about the total number of add operations
   * within each of the response time buckets.  The mapping will be between
   * the lower bound for the processing time bucket in milliseconds and the
   * number of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the total number of add operations
   *          within each of the response time buckets, or an empty map if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Long> getAddOpsCount()
  {
    return addOpsCount;
  }



  /**
   * Retrieves a map with information about the percentage of add operations
   * within each of the response time buckets.  The mapping will be between the
   * lower bound for the processing time bucket in milliseconds and the
   * percentage of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the percentage of add operations
   *          within each of the response time buckets, or an empty map if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getAddOpsPercent()
  {
    return addOpsPercent;
  }



  /**
   * Retrieves a map with information about the aggregate percentage of add
   * operations within each of the response time buckets or one of the lower
   * response time buckets.  The mapping will be between the lower bound for the
   * processing time bucket in milliseconds and the aggregate percentage of
   * operations whose processing time fell within that or lower response time
   * buckets.
   *
   * @return  A map with information about the aggregate percentage of add
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getAddOpsAggregatePercent()
  {
    return addOpsAggregatePercent;
  }



  /**
   * Retrieves the total number of bind operations that have been performed
   * in the server.
   *
   * @return  The total number of bind operations that have been performed in
   *          the server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public final Long getBindOpsTotalCount()
  {
    return bindOpsTotalCount;
  }



  /**
   * Retrieves the average response time in milliseconds of bind operations
   * performed in the server.
   *
   * @return  The average response time in milliseconds of bind operations
   *          that have been performed in the server, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public final Double getBindOpsAverageResponseTimeMillis()
  {
    return bindOpsAvgResponseTimeMillis;
  }



  /**
   * Retrieves a map with information about the total number of bind operations
   * within each of the response time buckets.  The mapping will be between
   * the lower bound for the processing time bucket in milliseconds and the
   * number of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the total number of bind operations
   *          within each of the response time buckets, or an empty map if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Long> getBindOpsCount()
  {
    return bindOpsCount;
  }



  /**
   * Retrieves a map with information about the percentage of bind operations
   * within each of the response time buckets.  The mapping will be between the
   * lower bound for the processing time bucket in milliseconds and the
   * percentage of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the percentage of bind operations
   *          within each of the response time buckets, or an empty map if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getBindOpsPercent()
  {
    return bindOpsPercent;
  }



  /**
   * Retrieves a map with information about the aggregate percentage of bind
   * operations within each of the response time buckets or one of the lower
   * response time buckets.  The mapping will be between the lower bound for the
   * processing time bucket in milliseconds and the aggregate percentage of
   * operations whose processing time fell within that or lower response time
   * buckets.
   *
   * @return  A map with information about the aggregate percentage of bind
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getBindOpsAggregatePercent()
  {
    return bindOpsAggregatePercent;
  }



  /**
   * Retrieves the total number of compare operations that have been performed
   * in the server.
   *
   * @return  The total number of compare operations that have been performed in
   *          the server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public final Long getCompareOpsTotalCount()
  {
    return compareOpsTotalCount;
  }



  /**
   * Retrieves the average response time in milliseconds of compare operations
   * performed in the server.
   *
   * @return  The average response time in milliseconds of compare operations
   *          that have been performed in the server, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public final Double getCompareOpsAverageResponseTimeMillis()
  {
    return compareOpsAvgResponseTimeMillis;
  }



  /**
   * Retrieves a map with information about the total number of compare
   * operations within each of the response time buckets.  The mapping will
   * be between the lower bound for the processing time bucket in milliseconds
   * and the number of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the total number of compare
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Long> getCompareOpsCount()
  {
    return compareOpsCount;
  }



  /**
   * Retrieves a map with information about the percentage of compare operations
   * within each of the response time buckets.  The mapping will be between the
   * lower bound for the processing time bucket in milliseconds and the
   * percentage of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the percentage of compare operations
   *          within each of the response time buckets, or an empty map if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getCompareOpsPercent()
  {
    return compareOpsPercent;
  }



  /**
   * Retrieves a map with information about the aggregate percentage of compare
   * operations within each of the response time buckets or one of the lower
   * response time buckets.  The mapping will be between the lower bound for the
   * processing time bucket in milliseconds and the aggregate percentage of
   * operations whose processing time fell within that or lower response time
   * buckets.
   *
   * @return  A map with information about the aggregate percentage of compare
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getCompareOpsAggregatePercent()
  {
    return compareOpsAggregatePercent;
  }



  /**
   * Retrieves the total number of delete operations that have been performed
   * in the server.
   *
   * @return  The total number of delete operations that have been performed in
   *          the server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public final Long getDeleteOpsTotalCount()
  {
    return deleteOpsTotalCount;
  }



  /**
   * Retrieves the average response time in milliseconds of delete operations
   * performed in the server.
   *
   * @return  The average response time in milliseconds of delete operations
   *          that have been performed in the server, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public final Double getDeleteOpsAverageResponseTimeMillis()
  {
    return deleteOpsAvgResponseTimeMillis;
  }



  /**
   * Retrieves a map with information about the total number of delete
   * operations within each of the response time buckets.  The mapping will
   * be between the lower bound for the processing time bucket in milliseconds
   * and the number of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the total number of delete
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Long> getDeleteOpsCount()
  {
    return deleteOpsCount;
  }



  /**
   * Retrieves a map with information about the percentage of delete operations
   * within each of the response time buckets.  The mapping will be between the
   * lower bound for the processing time bucket in milliseconds and the
   * percentage of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the percentage of delete operations
   *          within each of the response time buckets, or an empty map if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getDeleteOpsPercent()
  {
    return deleteOpsPercent;
  }



  /**
   * Retrieves a map with information about the aggregate percentage of delete
   * operations within each of the response time buckets or one of the lower
   * response time buckets.  The mapping will be between the lower bound for the
   * processing time bucket in milliseconds and the aggregate percentage of
   * operations whose processing time fell within that or lower response time
   * buckets.
   *
   * @return  A map with information about the aggregate percentage of delete
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getDeleteOpsAggregatePercent()
  {
    return deleteOpsAggregatePercent;
  }



  /**
   * Retrieves the total number of extended operations that have been performed
   * in the server.
   *
   * @return  The total number of extended operations that have been performed
   *          in the server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public final Long getExtendedOpsTotalCount()
  {
    return extendedOpsTotalCount;
  }



  /**
   * Retrieves the average response time in milliseconds of extended operations
   * performed in the server.
   *
   * @return  The average response time in milliseconds of extended operations
   *          that have been performed in the server, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public final Double getExtendedOpsAverageResponseTimeMillis()
  {
    return extendedOpsAvgResponseTimeMillis;
  }



  /**
   * Retrieves a map with information about the total number of extended
   * operations within each of the response time buckets.  The mapping will be
   * between the lower bound for the processing time bucket in milliseconds and
   * the number of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the total number of extended
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Long> getExtendedOpsCount()
  {
    return extendedOpsCount;
  }



  /**
   * Retrieves a map with information about the percentage of extended
   * operations within each of the response time buckets.  The mapping will be
   * between the lower bound for the processing time bucket in milliseconds and
   * the percentage of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the percentage of extended operations
   *          within each of the response time buckets, or an empty map if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getExtendedOpsPercent()
  {
    return extendedOpsPercent;
  }



  /**
   * Retrieves a map with information about the aggregate percentage of extended
   * operations within each of the response time buckets or one of the lower
   * response time buckets.  The mapping will be between the lower bound for the
   * processing time bucket in milliseconds and the aggregate percentage of
   * operations whose processing time fell within that or lower response time
   * buckets.
   *
   * @return  A map with information about the aggregate percentage of extended
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getExtendedOpsAggregatePercent()
  {
    return extendedOpsAggregatePercent;
  }



  /**
   * Retrieves the total number of modify operations that have been performed
   * in the server.
   *
   * @return  The total number of modify operations that have been performed in
   *          the server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public final Long getModifyOpsTotalCount()
  {
    return modifyOpsTotalCount;
  }



  /**
   * Retrieves the average response time in milliseconds of modify operations
   * performed in the server.
   *
   * @return  The average response time in milliseconds of modify operations
   *          that have been performed in the server, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public final Double getModifyOpsAverageResponseTimeMillis()
  {
    return modifyOpsAvgResponseTimeMillis;
  }



  /**
   * Retrieves a map with information about the total number of modify
   * operations within each of the response time buckets.  The mapping will
   * be between the lower bound for the processing time bucket in milliseconds
   * and the number of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the total number of modify
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Long> getModifyOpsCount()
  {
    return modifyOpsCount;
  }



  /**
   * Retrieves a map with information about the percentage of modify operations
   * within each of the response time buckets.  The mapping will be between the
   * lower bound for the processing time bucket in milliseconds and the
   * percentage of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the percentage of modify operations
   *          within each of the response time buckets, or an empty map if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getModifyOpsPercent()
  {
    return modifyOpsPercent;
  }



  /**
   * Retrieves a map with information about the aggregate percentage of modify
   * operations within each of the response time buckets or one of the lower
   * response time buckets.  The mapping will be between the lower bound for the
   * processing time bucket in milliseconds and the aggregate percentage of
   * operations whose processing time fell within that or lower response time
   * buckets.
   *
   * @return  A map with information about the aggregate percentage of modify
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getModifyOpsAggregatePercent()
  {
    return modifyOpsAggregatePercent;
  }



  /**
   * Retrieves a map with information about the total number of modify DN
   * operations within each of the response time buckets.  The mapping will
   * be between the lower bound for the processing time bucket in milliseconds
   * and the number of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the total number of modify DN
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Long> getModifyDNOpsCount()
  {
    return modifyDNOpsCount;
  }



  /**
   * Retrieves the total number of modify DN operations that have been performed
   * in the server.
   *
   * @return  The total number of modify DN operations that have been performed
   *          in the server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public final Long getModifyDNOpsTotalCount()
  {
    return modifyDNOpsTotalCount;
  }



  /**
   * Retrieves the average response time in milliseconds of modify DN operations
   * performed in the server.
   *
   * @return  The average response time in milliseconds of modify DN operations
   *          that have been performed in the server, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public final Double getModifyDNOpsAverageResponseTimeMillis()
  {
    return modifyDNOpsAvgResponseTimeMillis;
  }



  /**
   * Retrieves a map with information about the percentage of modify DN
   * operations within each of the response time buckets.  The mapping will be
   * between the lower bound for the processing time bucket in milliseconds and
   * the percentage of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the percentage of modify DN
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getModifyDNOpsPercent()
  {
    return modifyDNOpsPercent;
  }



  /**
   * Retrieves a map with information about the aggregate percentage of modify
   * DN operations within each of the response time buckets or one of the lower
   * response time buckets.  The mapping will be between the lower bound for the
   * processing time bucket in milliseconds and the aggregate percentage of
   * operations whose processing time fell within that or lower response time
   * buckets.
   *
   * @return  A map with information about the aggregate percentage of modify DN
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getModifyDNOpsAggregatePercent()
  {
    return modifyDNOpsAggregatePercent;
  }



  /**
   * Retrieves the total number of search operations that have been performed
   * in the server.
   *
   * @return  The total number of search operations that have been performed in
   *          the server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public final Long getSearchOpsTotalCount()
  {
    return searchOpsTotalCount;
  }



  /**
   * Retrieves the average response time in milliseconds of search operations
   * performed in the server.
   *
   * @return  The average response time in milliseconds of search operations
   *          that have been performed in the server, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public final Double getSearchOpsAverageResponseTimeMillis()
  {
    return searchOpsAvgResponseTimeMillis;
  }



  /**
   * Retrieves a map with information about the total number of search
   * operations within each of the response time buckets.  The mapping will
   * be between the lower bound for the processing time bucket in milliseconds
   * and the number of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the total number of search
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Long> getSearchOpsCount()
  {
    return searchOpsCount;
  }



  /**
   * Retrieves a map with information about the percentage of search operations
   * within each of the response time buckets.  The mapping will be between the
   * lower bound for the processing time bucket in milliseconds and the
   * percentage of operations whose processing time fell within that bucket.
   *
   * @return  A map with information about the percentage of search operations
   *          within each of the response time buckets, or an empty map if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getSearchOpsPercent()
  {
    return searchOpsPercent;
  }



  /**
   * Retrieves a map with information about the aggregate percentage of search
   * operations within each of the response time buckets or one of the lower
   * response time buckets.  The mapping will be between the lower bound for the
   * processing time bucket in milliseconds and the aggregate percentage of
   * operations whose processing time fell within that or lower response time
   * buckets.
   *
   * @return  A map with information about the aggregate percentage of search
   *          operations within each of the response time buckets, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public final Map<Long,Double> getSearchOpsAggregatePercent()
  {
    return searchOpsAggregatePercent;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_PROCESSING_TIME_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_PROCESSING_TIME_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(50));

    if (allOpsTotalCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ALL_TOTAL_COUNT,
           INFO_PROCESSING_TIME_DISPNAME_ALL_TOTAL_COUNT.get(),
           INFO_PROCESSING_TIME_DESC_ALL_TOTAL_COUNT.get(),
           allOpsTotalCount);
    }

    if (allOpsAvgResponseTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ALL_AVERAGE_RESPONSE_TIME_MS,
           INFO_PROCESSING_TIME_DISPNAME_ALL_TOTAL_TIME.get(),
           INFO_PROCESSING_TIME_DESC_ALL_TOTAL_TIME.get(),
           allOpsAvgResponseTimeMillis);
    }

    if (! allOpsCount.isEmpty())
    {
      final Iterator<Long> iterator = allOpsCount.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "allOpsCount-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_ALL_COUNT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_ALL_COUNT.get(lastValue, value),
             allOpsCount.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "allOpsCount-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_ALL_COUNT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_ALL_COUNT_LAST.get(lastValue),
               allOpsCount.get(lastValue));
        }
      }
    }

    if (! allOpsPercent.isEmpty())
    {
      final Iterator<Long> iterator = allOpsPercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "allOpsPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_ALL_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_ALL_PCT.get(lastValue, value),
             allOpsPercent.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "allOpsPct-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_ALL_PCT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_ALL_PCT_LAST.get(lastValue),
               allOpsPercent.get(lastValue));
        }
      }
    }

    if (! allOpsAggregatePercent.isEmpty())
    {
      final Iterator<Long> iterator =
           allOpsAggregatePercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "allOpsAggrPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_ALL_AGGR_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_ALL_AGGR_PCT.get(lastValue, value),
             allOpsAggregatePercent.get(lastValue));

        lastValue = value;
      }
    }

    if (addOpsTotalCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ADD_TOTAL_COUNT,
           INFO_PROCESSING_TIME_DISPNAME_ADD_TOTAL_COUNT.get(),
           INFO_PROCESSING_TIME_DESC_ADD_TOTAL_COUNT.get(),
           addOpsTotalCount);
    }

    if (addOpsAvgResponseTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ADD_AVERAGE_RESPONSE_TIME_MS,
           INFO_PROCESSING_TIME_DISPNAME_ADD_TOTAL_TIME.get(),
           INFO_PROCESSING_TIME_DESC_ADD_TOTAL_TIME.get(),
           addOpsAvgResponseTimeMillis);
    }

    if (! addOpsCount.isEmpty())
    {
      final Iterator<Long> iterator = addOpsCount.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "addOpsCount-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_ADD_COUNT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_ADD_COUNT.get(lastValue, value),
             addOpsCount.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "addOpsCount-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_ADD_COUNT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_ADD_COUNT_LAST.get(lastValue),
               addOpsCount.get(lastValue));
        }
      }
    }

    if (! addOpsPercent.isEmpty())
    {
      final Iterator<Long> iterator = addOpsPercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "addOpsPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_ADD_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_ADD_PCT.get(lastValue, value),
             addOpsPercent.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "addOpsPct-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_ADD_PCT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_ADD_PCT_LAST.get(lastValue),
               addOpsPercent.get(lastValue));
        }
      }
    }

    if (! addOpsAggregatePercent.isEmpty())
    {
      final Iterator<Long> iterator =
           addOpsAggregatePercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "addOpsAggrPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_ADD_AGGR_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_ADD_AGGR_PCT.get(lastValue, value),
             addOpsAggregatePercent.get(lastValue));

        lastValue = value;
      }
    }

    if (bindOpsTotalCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BIND_TOTAL_COUNT,
           INFO_PROCESSING_TIME_DISPNAME_BIND_TOTAL_COUNT.get(),
           INFO_PROCESSING_TIME_DESC_BIND_TOTAL_COUNT.get(),
           bindOpsTotalCount);
    }

    if (bindOpsAvgResponseTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BIND_AVERAGE_RESPONSE_TIME_MS,
           INFO_PROCESSING_TIME_DISPNAME_BIND_TOTAL_TIME.get(),
           INFO_PROCESSING_TIME_DESC_BIND_TOTAL_TIME.get(),
           bindOpsAvgResponseTimeMillis);
    }

    if (! bindOpsCount.isEmpty())
    {
      final Iterator<Long> iterator = bindOpsCount.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "bindOpsCount-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_BIND_COUNT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_BIND_COUNT.get(lastValue, value),
             bindOpsCount.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "bindOpsCount-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_BIND_COUNT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_BIND_COUNT_LAST.get(lastValue),
               bindOpsCount.get(lastValue));
        }
      }
    }

    if (! bindOpsPercent.isEmpty())
    {
      final Iterator<Long> iterator = bindOpsPercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "bindOpsPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_BIND_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_BIND_PCT.get(lastValue, value),
             bindOpsPercent.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "bindOpsPct-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_BIND_PCT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_BIND_PCT_LAST.get(lastValue),
               bindOpsPercent.get(lastValue));
        }
      }
    }

    if (! bindOpsAggregatePercent.isEmpty())
    {
      final Iterator<Long> iterator =
           bindOpsAggregatePercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "bindOpsAggrPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_BIND_AGGR_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_BIND_AGGR_PCT.get(lastValue, value),
             bindOpsAggregatePercent.get(lastValue));

        lastValue = value;
      }
    }

    if (compareOpsTotalCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMPARE_TOTAL_COUNT,
           INFO_PROCESSING_TIME_DISPNAME_COMPARE_TOTAL_COUNT.get(),
           INFO_PROCESSING_TIME_DESC_COMPARE_TOTAL_COUNT.get(),
           compareOpsTotalCount);
    }

    if (compareOpsAvgResponseTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMPARE_AVERAGE_RESPONSE_TIME_MS,
           INFO_PROCESSING_TIME_DISPNAME_COMPARE_TOTAL_TIME.get(),
           INFO_PROCESSING_TIME_DESC_COMPARE_TOTAL_TIME.get(),
           compareOpsAvgResponseTimeMillis);
    }

    if (! compareOpsCount.isEmpty())
    {
      final Iterator<Long> iterator = compareOpsCount.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "compareOpsCount-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_COMPARE_COUNT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_COMPARE_COUNT.get(lastValue, value),
             compareOpsCount.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "compareOpsCount-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_COMPARE_COUNT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_COMPARE_COUNT_LAST.get(lastValue),
               compareOpsCount.get(lastValue));
        }
      }
    }

    if (! compareOpsPercent.isEmpty())
    {
      final Iterator<Long> iterator = compareOpsPercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "compareOpsPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_COMPARE_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_COMPARE_PCT.get(lastValue, value),
             compareOpsPercent.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "compareOpsPct-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_COMPARE_PCT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_COMPARE_PCT_LAST.get(lastValue),
               compareOpsPercent.get(lastValue));
        }
      }
    }

    if (! compareOpsAggregatePercent.isEmpty())
    {
      final Iterator<Long> iterator =
           compareOpsAggregatePercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "compareOpsAggrPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_COMPARE_AGGR_PCT.get(lastValue,
                                                                value),
             INFO_PROCESSING_TIME_DESC_COMPARE_AGGR_PCT.get(lastValue, value),
             compareOpsAggregatePercent.get(lastValue));

        lastValue = value;
      }
    }

    if (deleteOpsTotalCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DELETE_TOTAL_COUNT,
           INFO_PROCESSING_TIME_DISPNAME_DELETE_TOTAL_COUNT.get(),
           INFO_PROCESSING_TIME_DESC_DELETE_TOTAL_COUNT.get(),
           deleteOpsTotalCount);
    }

    if (deleteOpsAvgResponseTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DELETE_AVERAGE_RESPONSE_TIME_MS,
           INFO_PROCESSING_TIME_DISPNAME_DELETE_TOTAL_TIME.get(),
           INFO_PROCESSING_TIME_DESC_DELETE_TOTAL_TIME.get(),
           deleteOpsAvgResponseTimeMillis);
    }

    if (! deleteOpsCount.isEmpty())
    {
      final Iterator<Long> iterator = deleteOpsCount.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "deleteOpsCount-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_DELETE_COUNT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_DELETE_COUNT.get(lastValue, value),
             deleteOpsCount.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "deleteOpsCount-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_DELETE_COUNT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_DELETE_COUNT_LAST.get(lastValue),
               deleteOpsCount.get(lastValue));
        }
      }
    }

    if (! deleteOpsPercent.isEmpty())
    {
      final Iterator<Long> iterator = deleteOpsPercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "deleteOpsPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_DELETE_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_DELETE_PCT.get(lastValue, value),
             deleteOpsPercent.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "deleteOpsPct-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_DELETE_PCT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_DELETE_PCT_LAST.get(lastValue),
               deleteOpsPercent.get(lastValue));
        }
      }
    }

    if (! deleteOpsAggregatePercent.isEmpty())
    {
      final Iterator<Long> iterator =
           deleteOpsAggregatePercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "deleteOpsAggrPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_DELETE_AGGR_PCT.get(lastValue,
                                                               value),
             INFO_PROCESSING_TIME_DESC_DELETE_AGGR_PCT.get(lastValue, value),
             deleteOpsAggregatePercent.get(lastValue));

        lastValue = value;
      }
    }

    if (extendedOpsTotalCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_EXTENDED_TOTAL_COUNT,
           INFO_PROCESSING_TIME_DISPNAME_EXTENDED_TOTAL_COUNT.get(),
           INFO_PROCESSING_TIME_DESC_EXTENDED_TOTAL_COUNT.get(),
           extendedOpsTotalCount);
    }

    if (extendedOpsAvgResponseTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_EXTENDED_AVERAGE_RESPONSE_TIME_MS,
           INFO_PROCESSING_TIME_DISPNAME_EXTENDED_TOTAL_TIME.get(),
           INFO_PROCESSING_TIME_DESC_EXTENDED_TOTAL_TIME.get(),
           extendedOpsAvgResponseTimeMillis);
    }

    if (! extendedOpsCount.isEmpty())
    {
      final Iterator<Long> iterator = extendedOpsCount.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "extendedOpsCount-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_EXTENDED_COUNT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_EXTENDED_COUNT.get(lastValue, value),
             extendedOpsCount.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "extendedOpsCount-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_EXTENDED_COUNT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_EXTENDED_COUNT_LAST.get(lastValue),
               extendedOpsCount.get(lastValue));
        }
      }
    }

    if (! extendedOpsPercent.isEmpty())
    {
      final Iterator<Long> iterator = extendedOpsPercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "extendedOpsPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_EXTENDED_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_EXTENDED_PCT.get(lastValue, value),
             extendedOpsPercent.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "extendedOpsPct-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_EXTENDED_PCT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_EXTENDED_PCT_LAST.get(lastValue),
               extendedOpsPercent.get(lastValue));
        }
      }
    }

    if (! extendedOpsAggregatePercent.isEmpty())
    {
      final Iterator<Long> iterator =
           extendedOpsAggregatePercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "extendedOpsAggrPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_EXTENDED_AGGR_PCT.get(lastValue,
                                                                 value),
             INFO_PROCESSING_TIME_DESC_EXTENDED_AGGR_PCT.get(lastValue, value),
             extendedOpsAggregatePercent.get(lastValue));

        lastValue = value;
      }
    }

    if (modifyOpsTotalCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_TOTAL_COUNT,
           INFO_PROCESSING_TIME_DISPNAME_MODIFY_TOTAL_COUNT.get(),
           INFO_PROCESSING_TIME_DESC_MODIFY_TOTAL_COUNT.get(),
           modifyOpsTotalCount);
    }

    if (modifyOpsAvgResponseTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_AVERAGE_RESPONSE_TIME_MS,
           INFO_PROCESSING_TIME_DISPNAME_MODIFY_TOTAL_TIME.get(),
           INFO_PROCESSING_TIME_DESC_MODIFY_TOTAL_TIME.get(),
           modifyOpsAvgResponseTimeMillis);
    }

    if (! modifyOpsCount.isEmpty())
    {
      final Iterator<Long> iterator = modifyOpsCount.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "modifyOpsCount-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_MODIFY_COUNT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_MODIFY_COUNT.get(lastValue, value),
             modifyOpsCount.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "modifyOpsCount-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_MODIFY_COUNT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_MODIFY_COUNT_LAST.get(lastValue),
               modifyOpsCount.get(lastValue));
        }
      }
    }

    if (! modifyOpsPercent.isEmpty())
    {
      final Iterator<Long> iterator = modifyOpsPercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "modifyOpsPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_MODIFY_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_MODIFY_PCT.get(lastValue, value),
             modifyOpsPercent.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "modifyOpsPct-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_MODIFY_PCT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_MODIFY_PCT_LAST.get(lastValue),
               modifyOpsPercent.get(lastValue));
        }
      }
    }

    if (! modifyOpsAggregatePercent.isEmpty())
    {
      final Iterator<Long> iterator =
           modifyOpsAggregatePercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "modifyOpsAggrPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_MODIFY_AGGR_PCT.get(lastValue,
                                                               value),
             INFO_PROCESSING_TIME_DESC_MODIFY_AGGR_PCT.get(lastValue, value),
             modifyOpsAggregatePercent.get(lastValue));

        lastValue = value;
      }
    }

    if (modifyDNOpsTotalCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_DN_TOTAL_COUNT,
           INFO_PROCESSING_TIME_DISPNAME_MODIFY_DN_TOTAL_COUNT.get(),
           INFO_PROCESSING_TIME_DESC_MODIFY_DN_TOTAL_COUNT.get(),
           modifyDNOpsTotalCount);
    }

    if (modifyDNOpsAvgResponseTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_DN_AVERAGE_RESPONSE_TIME_MS,
           INFO_PROCESSING_TIME_DISPNAME_MODIFY_DN_TOTAL_TIME.get(),
           INFO_PROCESSING_TIME_DESC_MODIFY_DN_TOTAL_TIME.get(),
           modifyDNOpsAvgResponseTimeMillis);
    }

    if (! modifyDNOpsCount.isEmpty())
    {
      final Iterator<Long> iterator = modifyDNOpsCount.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "modifyDNOpsCount-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_MODIFY_DN_COUNT.get(lastValue,
                                                               value),
             INFO_PROCESSING_TIME_DESC_MODIFY_DN_COUNT.get(lastValue, value),
             modifyDNOpsCount.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "modifyDNOpsCount-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_MODIFY_DN_COUNT_LAST.get(
                    lastValue),
               INFO_PROCESSING_TIME_DESC_MODIFY_DN_COUNT_LAST.get(lastValue),
               modifyDNOpsCount.get(lastValue));
        }
      }
    }

    if (! modifyDNOpsPercent.isEmpty())
    {
      final Iterator<Long> iterator = modifyDNOpsPercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "modifyDNOpsPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_MODIFY_DN_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_MODIFY_DN_PCT.get(lastValue, value),
             modifyDNOpsPercent.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "modifyDNOpsPct-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_MODIFY_DN_PCT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_MODIFY_DN_PCT_LAST.get(lastValue),
               modifyDNOpsPercent.get(lastValue));
        }
      }
    }

    if (! modifyDNOpsAggregatePercent.isEmpty())
    {
      final Iterator<Long> iterator =
           modifyDNOpsAggregatePercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "modifyDNOpsAggrPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_MODIFY_DN_AGGR_PCT.get(lastValue,
                                                                  value),
             INFO_PROCESSING_TIME_DESC_MODIFY_DN_AGGR_PCT.get(lastValue, value),
             modifyDNOpsAggregatePercent.get(lastValue));

        lastValue = value;
      }
    }

    if (searchOpsTotalCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_TOTAL_COUNT,
           INFO_PROCESSING_TIME_DISPNAME_SEARCH_TOTAL_COUNT.get(),
           INFO_PROCESSING_TIME_DESC_SEARCH_TOTAL_COUNT.get(),
           searchOpsTotalCount);
    }

    if (searchOpsAvgResponseTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_AVERAGE_RESPONSE_TIME_MS,
           INFO_PROCESSING_TIME_DISPNAME_SEARCH_TOTAL_TIME.get(),
           INFO_PROCESSING_TIME_DESC_SEARCH_TOTAL_TIME.get(),
           searchOpsAvgResponseTimeMillis);
    }

    if (! searchOpsCount.isEmpty())
    {
      final Iterator<Long> iterator = searchOpsCount.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "searchOpsCount-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_SEARCH_COUNT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_SEARCH_COUNT.get(lastValue, value),
             searchOpsCount.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "searchOpsCount-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_SEARCH_COUNT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_SEARCH_COUNT_LAST.get(lastValue),
               searchOpsCount.get(lastValue));
        }
      }
    }

    if (! searchOpsPercent.isEmpty())
    {
      final Iterator<Long> iterator = searchOpsPercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "searchOpsPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_SEARCH_PCT.get(lastValue, value),
             INFO_PROCESSING_TIME_DESC_SEARCH_PCT.get(lastValue, value),
             searchOpsPercent.get(lastValue));

        lastValue = value;
        if (! iterator.hasNext())
        {
          addMonitorAttribute(attrs,
               "searchOpsPct-" + lastValue,
               INFO_PROCESSING_TIME_DISPNAME_SEARCH_PCT_LAST.get(lastValue),
               INFO_PROCESSING_TIME_DESC_SEARCH_PCT_LAST.get(lastValue),
               searchOpsPercent.get(lastValue));
        }
      }
    }

    if (! searchOpsAggregatePercent.isEmpty())
    {
      final Iterator<Long> iterator =
           searchOpsAggregatePercent.keySet().iterator();
      Long lastValue = iterator.next();

      while (iterator.hasNext())
      {
        final Long value = iterator.next();
        addMonitorAttribute(attrs,
             "searchOpsAggrPct-" + lastValue + '-' + value,
             INFO_PROCESSING_TIME_DISPNAME_SEARCH_AGGR_PCT.get(lastValue,
                                                               value),
             INFO_PROCESSING_TIME_DESC_SEARCH_AGGR_PCT.get(lastValue, value),
             searchOpsAggregatePercent.get(lastValue));

        lastValue = value;
      }
    }

    return Collections.unmodifiableMap(attrs);
  }
}
