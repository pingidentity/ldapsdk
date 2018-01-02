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



import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a numeric gauge monitor entry, which obtains its
 * information from a numeric value in a monitor entry.
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
public final class NumericGaugeMonitorEntry
       extends GaugeMonitorEntry
{
  /**
   * The structural object class used in gauge monitor entries.
   */
  static final String NUMERIC_GAUGE_MONITOR_OC =
       "ds-numeric-gauge-monitor-entry";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2049893927290436280L;



  // The current value for the gauge.
  private final Double currentValue;

  // The maximum value observed for the gauge.
  private final Double maximumValue;

  // The minimum value observed for the gauge.
  private final Double minimumValue;

  // The current value for the gauge.
  private final Double previousValue;

  // The set of observed values for the gauge.
  private final List<Double> observedValues;



  /**
   * Creates a new numeric gauge monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a numeric gauge monitor entry.  It
   *                must not be {@code null}.
   */
  public NumericGaugeMonitorEntry(final Entry entry)
  {
    super(entry);

    currentValue = getDouble("value");
    previousValue = getDouble("previous-value");
    minimumValue = getDouble("value-minimum");
    maximumValue = getDouble("value-maximum");

    final String observedStr = getString("observed-values");
    if ((observedStr == null) || (observedStr.length() == 0))
    {
      observedValues = Collections.emptyList();
    }
    else
    {
      final ArrayList<Double> values = new ArrayList<Double>(10);
      try
      {
        final StringTokenizer tokenizer = new StringTokenizer(observedStr, ",");
        while (tokenizer.hasMoreTokens())
        {
          values.add(Double.parseDouble(tokenizer.nextToken()));
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        values.clear();
      }

      observedValues = Collections.unmodifiableList(values);
    }
  }



  /**
   * Retrieves the current value for the gauge, if available.
   *
   * @return  The current value for the gauge, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Double getCurrentValue()
  {
    return currentValue;
  }



  /**
   * Retrieves the previous value for the gauge, if available.
   *
   * @return  The previous value for the gauge, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Double getPreviousValue()
  {
    return previousValue;
  }



  /**
   * Retrieves the minimum value observed for the gauge, if available.
   *
   * @return  The minimum value observed for the gauge, or {@code null} if it
   *          was not included in the monitor entry.
   */
  public Double getMinimumValue()
  {
    return minimumValue;
  }



  /**
   * Retrieves the maximum value observed for the gauge, if available.
   *
   * @return  The maximum value observed for the gauge, or {@code null} if it
   *          was not included in the monitor entry.
   */
  public Double getMaximumValue()
  {
    return maximumValue;
  }



  /**
   * Retrieves the set of observed values for the gauge, if available.
   *
   * @return  The set of observed values for the gauge, or {@code null} if it
   *          was not included in the monitor entry.
   */
  public List<Double> getObservedValues()
  {
    return observedValues;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDisplayName()
  {
    return INFO_NUMERIC_GAUGE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDescription()
  {
    return INFO_NUMERIC_GAUGE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final Map<String,MonitorAttribute> superAttributes =
         super.getMonitorAttributes();

    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<String,MonitorAttribute>(superAttributes.size() + 5);
    attrs.putAll(superAttributes);

    if (currentValue != null)
    {
      addMonitorAttribute(attrs,
           "value",
           INFO_NUMERIC_GAUGE_DISPNAME_CURRENT_VALUE.get(),
           INFO_NUMERIC_GAUGE_DESC_CURRENT_VALUE.get(),
           currentValue);
    }

    if (previousValue != null)
    {
      addMonitorAttribute(attrs,
           "previous-value",
           INFO_NUMERIC_GAUGE_DISPNAME_PREVIOUS_VALUE.get(),
           INFO_NUMERIC_GAUGE_DESC_PREVIOUS_VALUE.get(),
           previousValue);
    }

    if (minimumValue != null)
    {
      addMonitorAttribute(attrs,
           "value-minimum",
           INFO_NUMERIC_GAUGE_DISPNAME_MINIMUM_VALUE.get(),
           INFO_NUMERIC_GAUGE_DESC_MINIMUM_VALUE.get(),
           minimumValue);
    }

    if (maximumValue != null)
    {
      addMonitorAttribute(attrs,
           "value-maximum",
           INFO_NUMERIC_GAUGE_DISPNAME_MAXIMUM_VALUE.get(),
           INFO_NUMERIC_GAUGE_DESC_MAXIMUM_VALUE.get(),
           maximumValue);
    }

    if (! observedValues.isEmpty())
    {
      final Double[] values = new Double[observedValues.size()];
      observedValues.toArray(values);

      attrs.put("observed-values",
           new MonitorAttribute("observed-values",
                INFO_NUMERIC_GAUGE_DISPNAME_OBSERVED_VALUES.get(),
                INFO_NUMERIC_GAUGE_DESC_OBSERVED_VALUES.get(),
                values));
    }

    return Collections.unmodifiableMap(attrs);
  }
}
