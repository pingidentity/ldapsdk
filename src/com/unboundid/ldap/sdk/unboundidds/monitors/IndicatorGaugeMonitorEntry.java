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



import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines an indicator gauge monitor entry, which obtains its
 * information from a non-numeric value in a monitor entry.
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
public final class IndicatorGaugeMonitorEntry
       extends GaugeMonitorEntry
{
  /**
   * The structural object class used in gauge monitor entries.
   */
  @NotNull static final String INDICATOR_GAUGE_MONITOR_OC =
       "ds-indicator-gauge-monitor-entry";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6487368235968435879L;



  // The set of observed values for the gauge.
  @NotNull private final List<String> observedValues;

  // The current value for the gauge.
  @Nullable private final String currentValue;

  // The previous value observed for the gauge.
  @Nullable private final String previousValue;



  /**
   * Creates a new indicator gauge monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a indicator gauge monitor entry.
   *                It must not be {@code null}.
   */
  public IndicatorGaugeMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    currentValue = getString("value");
    previousValue = getString("previous-value");

    final String observedValuesStr = getString("observed-values");
    if (observedValuesStr == null)
    {
      observedValues = Collections.emptyList();
    }
    else
    {
      final ArrayList<String> valueList = new ArrayList<>(10);
      final StringTokenizer tokenizer =
           new StringTokenizer(observedValuesStr, ",");
      while (tokenizer.hasMoreTokens())
      {
        valueList.add(tokenizer.nextToken());
      }
      observedValues = Collections.unmodifiableList(valueList);
    }
  }



  /**
   * Retrieves the current value for the gauge, if available.
   *
   * @return The current value for the gauge, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getCurrentValue()
  {
    return currentValue;
  }



  /**
   * Retrieves the previous value for the gauge, if available.
   *
   * @return  The previous value for the gauge, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getPreviousValue()
  {
    return previousValue;
  }



  /**
   * Retrieves the set of observed values for the gauge, if available.
   *
   * @return  The set of observed values for the gauge, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @NotNull()
  public List<String> getObservedValues()
  {
    return observedValues;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_INDICATOR_GAUGE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_INDICATOR_GAUGE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final Map<String,MonitorAttribute> superAttributes =
         super.getMonitorAttributes();

    final LinkedHashMap<String,MonitorAttribute> attrs = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(superAttributes.size() + 3));
    attrs.putAll(superAttributes);

    if (currentValue != null)
    {
      addMonitorAttribute(attrs,
           "value",
           INFO_INDICATOR_GAUGE_DISPNAME_CURRENT_VALUE.get(),
           INFO_INDICATOR_GAUGE_DESC_CURRENT_VALUE.get(),
           currentValue);
    }

    if (previousValue != null)
    {
      addMonitorAttribute(attrs,
           "previous-value",
           INFO_INDICATOR_GAUGE_DISPNAME_PREVIOUS_VALUE.get(),
           INFO_INDICATOR_GAUGE_DESC_PREVIOUS_VALUE.get(),
           previousValue);
    }

    if (! observedValues.isEmpty())
    {
      addMonitorAttribute(attrs,
           "observed-values",
           INFO_INDICATOR_GAUGE_DISPNAME_OBSERVED_VALUES.get(),
           INFO_INDICATOR_GAUGE_DESC_OBSERVED_VALUES.get(),
           observedValues);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
