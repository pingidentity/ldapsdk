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
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the result
 * codes returned from various types of operations.
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
public final class ResultCodeMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in group cache monitor entries.
   */
  @NotNull static final String RESULT_CODE_MONITOR_OC =
       "ds-ldap-result-codes-monitor-entry";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -963682306039266913L;



  // The result code information for extended operations.
  @NotNull private final ExtendedOperationResultCodeInfo
       extendedOperationResultCodeInfo;

  // The result code information for add operations.
  @NotNull private final OperationResultCodeInfo addOperationResultCodeInfo;

  // The result code information for all types of operations.
  @NotNull private final OperationResultCodeInfo allOperationsResultCodeInfo;

  // The result code information for bind operations.
  @NotNull private final OperationResultCodeInfo bindOperationResultCodeInfo;

  // The result code information for compare operations.
  @NotNull private final OperationResultCodeInfo
       compareOperationResultCodeInfo;

  // The result code information for delete operations.
  @NotNull private final OperationResultCodeInfo deleteOperationResultCodeInfo;

  // The result code information for modify operations.
  @NotNull private final OperationResultCodeInfo modifyOperationResultCodeInfo;

  // The result code information for modify DN operations.
  @NotNull private final OperationResultCodeInfo
       modifyDNOperationResultCodeInfo;

  // The result code information for search operations.
  @NotNull private final OperationResultCodeInfo searchOperationResultCodeInfo;



  /**
   * Creates a new result code monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a result code monitor entry.  It
   *                must not be {@code null}.
   */
  public ResultCodeMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    allOperationsResultCodeInfo =
         new OperationResultCodeInfo(this, null, "all-ops-");
    addOperationResultCodeInfo =
         new OperationResultCodeInfo(this, OperationType.ADD, "add-op-");
    bindOperationResultCodeInfo =
         new OperationResultCodeInfo(this, OperationType.BIND, "bind-op-");
    compareOperationResultCodeInfo =
         new OperationResultCodeInfo(this, OperationType.COMPARE,
              "compare-op-");
    deleteOperationResultCodeInfo =
         new OperationResultCodeInfo(this, OperationType.DELETE, "delete-op-");
    extendedOperationResultCodeInfo = new ExtendedOperationResultCodeInfo(this);
    modifyOperationResultCodeInfo =
         new OperationResultCodeInfo(this, OperationType.MODIFY, "modify-op-");
    modifyDNOperationResultCodeInfo =
         new OperationResultCodeInfo(this, OperationType.MODIFY_DN,
              "modifydn-op-");
    searchOperationResultCodeInfo =
         new OperationResultCodeInfo(this, OperationType.SEARCH, "search-op-");
  }



  /**
   * Retrieves result code information that encompasses all types of operations.
   *
   * @return  Result code information that encompasses all types of operations.
   */
  @NotNull()
  public OperationResultCodeInfo getAllOperationsResultCodeInfo()
  {
    return allOperationsResultCodeInfo;
  }



  /**
   * Retrieves result code information for add operations.
   *
   * @return  Result code information for add operations.
   */
  @NotNull()
  public OperationResultCodeInfo getAddOperationResultCodeInfo()
  {
    return addOperationResultCodeInfo;
  }



  /**
   * Retrieves result code information for bind operations.
   *
   * @return  Result code information for bind operations.
   */
  @NotNull()
  public OperationResultCodeInfo getBindOperationResultCodeInfo()
  {
    return bindOperationResultCodeInfo;
  }



  /**
   * Retrieves result code information for compare operations.
   *
   * @return  Result code information for compare operations.
   */
  @NotNull()
  public OperationResultCodeInfo getCompareOperationResultCodeInfo()
  {
    return compareOperationResultCodeInfo;
  }



  /**
   * Retrieves result code information for delete operations.
   *
   * @return  Result code information for delete operations.
   */
  @NotNull()
  public OperationResultCodeInfo getDeleteOperationResultCodeInfo()
  {
    return deleteOperationResultCodeInfo;
  }



  /**
   * Retrieves result code information for extended operations.
   *
   * @return  Result code information for extended operations.
   */
  @NotNull()
  public ExtendedOperationResultCodeInfo getExtendedOperationResultCodeInfo()
  {
    return extendedOperationResultCodeInfo;
  }



  /**
   * Retrieves result code information for modify operations.
   *
   * @return  Result code information for modify operations.
   */
  @NotNull()
  public OperationResultCodeInfo getModifyOperationResultCodeInfo()
  {
    return modifyOperationResultCodeInfo;
  }



  /**
   * Retrieves result code information for modify DN operations.
   *
   * @return  Result code information for modify DN operations.
   */
  @NotNull()
  public OperationResultCodeInfo getModifyDNOperationResultCodeInfo()
  {
    return modifyDNOperationResultCodeInfo;
  }



  /**
   * Retrieves result code information for search operations.
   *
   * @return  Result code information for search operations.
   */
  @NotNull()
  public OperationResultCodeInfo getSearchOperationResultCodeInfo()
  {
    return searchOperationResultCodeInfo;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_RESULT_CODE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_RESULT_CODE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(100));

    addAttrs(attrs, allOperationsResultCodeInfo, "all-ops-");
    addAttrs(attrs, addOperationResultCodeInfo, "add-op-");
    addAttrs(attrs, bindOperationResultCodeInfo, "bind-op-");
    addAttrs(attrs, compareOperationResultCodeInfo, "compare-op-");
    addAttrs(attrs, deleteOperationResultCodeInfo, "delete-op-");
    addAttrs(attrs, extendedOperationResultCodeInfo);
    addAttrs(attrs, modifyOperationResultCodeInfo, "modify-op-");
    addAttrs(attrs, modifyDNOperationResultCodeInfo, "modifydn-op-");
    addAttrs(attrs, searchOperationResultCodeInfo, "search-op-");

    return Collections.unmodifiableMap(attrs);
  }



  /**
   * Updates the provided map with information about an appropriate set of
   * monitor attributes.
   *
   * @param  attrs           The set of monitor attributes to be updated.
   * @param  resultCodeInfo  The result code information to use.
   * @param  attrPrefix      The attribute prefix
   */
  private static void addAttrs(
       @NotNull final LinkedHashMap<String,MonitorAttribute> attrs,
       @NotNull final OperationResultCodeInfo resultCodeInfo,
       @NotNull final String attrPrefix)
  {
    final String opName;
    if (resultCodeInfo.getOperationType() == null)
    {
      opName = INFO_RESULT_CODE_OP_NAME_ALL.get();
    }
    else
    {
      switch (resultCodeInfo.getOperationType())
      {
        case ADD:
          opName = INFO_RESULT_CODE_OP_NAME_ADD.get();
          break;
        case BIND:
          opName = INFO_RESULT_CODE_OP_NAME_BIND.get();
          break;
        case COMPARE:
          opName = INFO_RESULT_CODE_OP_NAME_COMPARE.get();
          break;
        case DELETE:
          opName = INFO_RESULT_CODE_OP_NAME_DELETE.get();
          break;
        case MODIFY:
          opName = INFO_RESULT_CODE_OP_NAME_MODIFY.get();
          break;
        case MODIFY_DN:
          opName = INFO_RESULT_CODE_OP_NAME_MODIFY_DN.get();
          break;
        case SEARCH:
          opName = INFO_RESULT_CODE_OP_NAME_SEARCH.get();
          break;
        default:
          opName = "Unknown";
          break;
      }
    }

    final String lowerOpName = StaticUtils.toLowerCase(opName);

    final Long totalCount = resultCodeInfo.getTotalCount();
    if (totalCount != null)
    {
      addMonitorAttribute(attrs,
           attrPrefix + "total-count",
           INFO_RESULT_CODE_DISPNAME_TOTAL_COUNT.get(opName),
           INFO_RESULT_CODE_DESC_TOTAL_COUNT.get(lowerOpName),
           totalCount);
    }

    final Long failedCount = resultCodeInfo.getFailedCount();
    if (failedCount != null)
    {
      addMonitorAttribute(attrs,
           attrPrefix + "failed-count",
           INFO_RESULT_CODE_DISPNAME_FAILED_COUNT.get(opName),
           INFO_RESULT_CODE_DESC_FAILED_COUNT.get(lowerOpName),
           failedCount);
    }

    final Double failedPercent = resultCodeInfo.getFailedPercent();
    if (failedPercent != null)
    {
      addMonitorAttribute(attrs,
           attrPrefix + "failed-percent",
           INFO_RESULT_CODE_DISPNAME_FAILED_PERCENT.get(opName),
           INFO_RESULT_CODE_DESC_FAILED_PERCENT.get(lowerOpName),
           failedPercent);
    }

    for (final ResultCodeInfo i :
         resultCodeInfo.getResultCodeInfoMap().values())
    {
      addMonitorAttribute(attrs,
           attrPrefix + i.intValue() + "-name",
           INFO_RESULT_CODE_DISPNAME_RC_NAME.get(opName, i.intValue()),
           INFO_RESULT_CODE_DESC_RC_NAME.get(lowerOpName, i.intValue()),
           i.getName());

      addMonitorAttribute(attrs,
           attrPrefix + i.intValue() + "-count",
           INFO_RESULT_CODE_DISPNAME_RC_COUNT.get(opName, i.intValue()),
           INFO_RESULT_CODE_DESC_RC_COUNT.get(lowerOpName, i.intValue()),
           i.getCount());

      addMonitorAttribute(attrs,
           attrPrefix + i.intValue() + "-percent",
           INFO_RESULT_CODE_DISPNAME_RC_PERCENT.get(opName, i.intValue()),
           INFO_RESULT_CODE_DESC_RC_PERCENT.get(lowerOpName, i.intValue()),
           i.getPercent());

      addMonitorAttribute(attrs,
           attrPrefix + i.intValue() + "-average-response-time-millis",
           INFO_RESULT_CODE_DISPNAME_RC_AVG_RT.get(opName, i.intValue()),
           INFO_RESULT_CODE_DESC_RC_AVG_RT.get(lowerOpName, i.intValue()),
           i.getAverageResponseTimeMillis());

      addMonitorAttribute(attrs,
           attrPrefix + i.intValue() + "-total-response-time-millis",
           INFO_RESULT_CODE_DISPNAME_RC_TOTAL_RT.get(opName, i.intValue()),
           INFO_RESULT_CODE_DESC_RC_TOTAL_RT.get(lowerOpName, i.intValue()),
           i.getTotalResponseTimeMillis());
    }
  }



  /**
   * Updates the provided map with information about an appropriate set of
   * monitor attributes.
   *
   * @param  attrs           The set of monitor attributes to be updated.
   * @param  resultCodeInfo  The result code information to use.
   */
  private static void addAttrs(
       @NotNull final LinkedHashMap<String,MonitorAttribute> attrs,
       @NotNull final ExtendedOperationResultCodeInfo resultCodeInfo)
  {
    final String opName = INFO_RESULT_CODE_OP_NAME_EXTENDED.get();
    final String lowerOpName = StaticUtils.toLowerCase(opName);

    final Long totalCount = resultCodeInfo.getTotalCount();
    if (totalCount != null)
    {
      addMonitorAttribute(attrs,
           "extended-op-total-count",
           INFO_RESULT_CODE_DISPNAME_TOTAL_COUNT.get(opName),
           INFO_RESULT_CODE_DESC_TOTAL_COUNT.get(lowerOpName),
           totalCount);
    }

    final Long failedCount = resultCodeInfo.getFailedCount();
    if (failedCount != null)
    {
      addMonitorAttribute(attrs,
           "extended-op-failed-count",
           INFO_RESULT_CODE_DISPNAME_FAILED_COUNT.get(opName),
           INFO_RESULT_CODE_DESC_FAILED_COUNT.get(lowerOpName),
           failedCount);
    }

    final Double failedPercent = resultCodeInfo.getFailedPercent();
    if (failedPercent != null)
    {
      addMonitorAttribute(attrs,
           "extended-op-failed-percent",
           INFO_RESULT_CODE_DISPNAME_FAILED_PERCENT.get(opName),
           INFO_RESULT_CODE_DESC_FAILED_PERCENT.get(lowerOpName),
           failedPercent);
    }

    for (final String oid :
         resultCodeInfo.getExtendedRequestNamesByOID().keySet())
    {
      final String prefix = "extended-op-" + oid.replace('.', '-') + '-';

      final String name =
           resultCodeInfo.getExtendedRequestNamesByOID().get(oid);
      if (name != null)
      {
        addMonitorAttribute(attrs,
             prefix + "name",
             INFO_RESULT_CODE_DISPNAME_EXTOP_NAME.get(oid),
             INFO_RESULT_CODE_DESC_EXTOP_NAME.get(oid),
             name);
      }

      final Long total = resultCodeInfo.getTotalCountsByOID().get(oid);
      if (total != null)
      {
        addMonitorAttribute(attrs,
             prefix + "total-count",
             INFO_RESULT_CODE_DISPNAME_EXTOP_TOTAL_COUNT.get(oid),
             INFO_RESULT_CODE_DESC_EXTOP_TOTAL_COUNT.get(oid),
             total);
      }

      final Long failed = resultCodeInfo.getFailedCountsByOID().get(oid);
      if (failed != null)
      {
        addMonitorAttribute(attrs,
             prefix + "failed-count",
             INFO_RESULT_CODE_DISPNAME_EXTOP_FAILED_COUNT.get(oid),
             INFO_RESULT_CODE_DESC_EXTOP_FAILED_COUNT.get(oid),
             failed);
      }

      final Double percent = resultCodeInfo.getFailedPercentsByOID().get(oid);
      if (percent != null)
      {
        addMonitorAttribute(attrs,
             prefix+ "failed-percent",
             INFO_RESULT_CODE_DISPNAME_EXTOP_FAILED_PERCENT.get(oid),
             INFO_RESULT_CODE_DESC_EXTOP_FAILED_PERCENT.get(oid),
             percent);
      }

      final Map<Integer,ResultCodeInfo> rcInfoMap =
           resultCodeInfo.getResultCodeInfoMap().get(oid);
      if (rcInfoMap != null)
      {
        for (final ResultCodeInfo rcInfo : rcInfoMap.values())
        {
          final int intValue = rcInfo.intValue();
          final String rcPrefix = prefix + intValue + '-';

          addMonitorAttribute(attrs,
               rcPrefix + "name",
               INFO_RESULT_CODE_DISPNAME_EXTOP_RC_NAME.get(oid, intValue),
               INFO_RESULT_CODE_DESC_EXTOP_RC_NAME.get(oid, intValue),
               rcInfo.getName());
          addMonitorAttribute(attrs,
               rcPrefix + "count",
               INFO_RESULT_CODE_DISPNAME_EXTOP_RC_COUNT.get(oid, intValue),
               INFO_RESULT_CODE_DESC_EXTOP_RC_COUNT.get(oid, intValue),
               rcInfo.getCount());
          addMonitorAttribute(attrs,
               rcPrefix + "percent",
               INFO_RESULT_CODE_DISPNAME_EXTOP_RC_PERCENT.get(oid, intValue),
               INFO_RESULT_CODE_DESC_EXTOP_RC_PERCENT.get(oid, intValue),
               rcInfo.getPercent());
          addMonitorAttribute(attrs,
               rcPrefix + "average-response-time-millis",
               INFO_RESULT_CODE_DISPNAME_EXTOP_RC_AVG_RT.get(oid, intValue),
               INFO_RESULT_CODE_DESC_EXTOP_RC_AVG_RT.get(oid, intValue),
               rcInfo.getAverageResponseTimeMillis());
          addMonitorAttribute(attrs,
               rcPrefix + "total-response-time-millis",
               INFO_RESULT_CODE_DISPNAME_EXTOP_RC_TOTAL_RT.get(oid, intValue),
               INFO_RESULT_CODE_DESC_EXTOP_RC_TOTAL_RT.get(oid, intValue),
               rcInfo.getTotalResponseTimeMillis());
        }
      }
    }
  }
}
