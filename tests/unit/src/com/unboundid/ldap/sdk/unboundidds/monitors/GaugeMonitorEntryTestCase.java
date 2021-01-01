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


import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.unboundidds.AlarmSeverity;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the GaugeMonitorEntry class.
 */
public class GaugeMonitorEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor with a valid entry with all
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorAllValues()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: cn=Test Gauge,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-gauge-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Test Gauge",
         "gauge-name: test-gauge-name",
         "resource: test-resource",
         "resource-type: test-resource-type",
         "severity: NORMAL",
         "previous-severity: WARNING",
         "summary: test-summary",
         "error-message: test-error-message-1",
         "error-message: test-error-message-2",
         "gauge-init-time: 20140102030405.678Z",
         "update-time: 20140102030405.679Z",
         "samples-this-interval: 1",
         "current-severity-start-time: 20140102030405.680Z",
         "current-severity-duration: 2 seconds",
         "current-severity-duration-millis: 2000",
         "last-normal-state-start-time: 20140102030405.681Z",
         "last-normal-state-end-time: 20140102030405.682Z",
         "last-normal-state-duration: 3 seconds",
         "last-normal-state-duration-millis: 3000",
         "total-normal-state-duration: 4 seconds",
         "total-normal-state-duration-millis: 4000",
         "last-warning-state-start-time: 20140102030405.683Z",
         "last-warning-state-end-time: 20140102030405.684Z",
         "last-warning-state-duration: 5 seconds",
         "last-warning-state-duration-millis: 5000",
         "total-warning-state-duration: 6 seconds",
         "total-warning-state-duration-millis: 6000",
         "last-minor-state-start-time: 20140102030405.685Z",
         "last-minor-state-end-time: 20140102030405.686Z",
         "last-minor-state-duration: 7 seconds",
         "last-minor-state-duration-millis: 7000",
         "total-minor-state-duration: 8 seconds",
         "total-minor-state-duration-millis: 8000",
         "last-major-state-start-time: 20140102030405.687Z",
         "last-major-state-end-time: 20140102030405.688Z",
         "last-major-state-duration: 9 seconds",
         "last-major-state-duration-millis: 9000",
         "total-major-state-duration: 10 seconds",
         "total-major-state-duration-millis: 10000",
         "last-critical-state-start-time: 20140102030405.689Z",
         "last-critical-state-end-time: 20140102030405.690Z",
         "last-critical-state-duration: 11 seconds",
         "last-critical-state-duration-millis: 11000",
         "total-critical-state-duration: 12 seconds",
         "total-critical-state-duration-millis: 12000");

    final GaugeMonitorEntry me = new GaugeMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-gauge-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         GaugeMonitorEntry.class.getName());

    assertNotNull(me.getGaugeName());
    assertEquals(me.getGaugeName(), "test-gauge-name");

    assertNotNull(me.getResource());
    assertEquals(me.getResource(), "test-resource");

    assertNotNull(me.getResourceType());
    assertEquals(me.getResourceType(), "test-resource-type");

    assertNotNull(me.getCurrentSeverity());
    assertEquals(me.getCurrentSeverity(), AlarmSeverity.NORMAL);

    assertNotNull(me.getPreviousSeverity());
    assertEquals(me.getPreviousSeverity(), AlarmSeverity.WARNING);

    assertNotNull(me.getSummary());
    assertEquals(me.getSummary(), "test-summary");

    assertNotNull(me.getErrorMessages());
    assertFalse(me.getErrorMessages().isEmpty());
    assertEquals(me.getErrorMessages().size(), 2);
    assertTrue(me.getErrorMessages().contains("test-error-message-1"));
    assertTrue(me.getErrorMessages().contains("test-error-message-2"));

    assertNotNull(me.getInitTime());
    assertEquals(me.getInitTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.678Z"));

    assertNotNull(me.getUpdateTime());
    assertEquals(me.getUpdateTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.679Z"));

    assertNotNull(me.getSamplesThisInterval());
    assertEquals(me.getSamplesThisInterval(), Long.valueOf(1L));

    assertNotNull(me.getCurrentSeverityStartTime());
    assertEquals(me.getCurrentSeverityStartTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.680Z"));

    assertNotNull(me.getCurrentSeverityDurationString());
    assertEquals(me.getCurrentSeverityDurationString(), "2 seconds");

    assertNotNull(me.getCurrentSeverityDurationMillis());
    assertEquals(me.getCurrentSeverityDurationMillis(), Long.valueOf(2000L));

    assertNotNull(me.getLastNormalStateStartTime());
    assertEquals(me.getLastNormalStateStartTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.681Z"));

    assertNotNull(me.getLastNormalStateEndTime());
    assertEquals(me.getLastNormalStateEndTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.682Z"));

    assertNotNull(me.getLastNormalStateDurationString());
    assertEquals(me.getLastNormalStateDurationString(), "3 seconds");

    assertNotNull(me.getLastNormalStateDurationMillis());
    assertEquals(me.getLastNormalStateDurationMillis(), Long.valueOf(3000L));

    assertNotNull(me.getTotalNormalStateDurationString());
    assertEquals(me.getTotalNormalStateDurationString(), "4 seconds");

    assertNotNull(me.getTotalNormalStateDurationMillis());
    assertEquals(me.getTotalNormalStateDurationMillis(), Long.valueOf(4000L));

    assertNotNull(me.getLastWarningStateStartTime());
    assertEquals(me.getLastWarningStateStartTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.683Z"));

    assertNotNull(me.getLastWarningStateEndTime());
    assertEquals(me.getLastWarningStateEndTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.684Z"));

    assertNotNull(me.getLastWarningStateDurationString());
    assertEquals(me.getLastWarningStateDurationString(), "5 seconds");

    assertNotNull(me.getLastWarningStateDurationMillis());
    assertEquals(me.getLastWarningStateDurationMillis(), Long.valueOf(5000L));

    assertNotNull(me.getTotalWarningStateDurationString());
    assertEquals(me.getTotalWarningStateDurationString(), "6 seconds");

    assertNotNull(me.getTotalWarningStateDurationMillis());
    assertEquals(me.getTotalWarningStateDurationMillis(), Long.valueOf(6000L));

    assertNotNull(me.getLastMinorStateStartTime());
    assertEquals(me.getLastMinorStateStartTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.685Z"));

    assertNotNull(me.getLastMinorStateEndTime());
    assertEquals(me.getLastMinorStateEndTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.686Z"));

    assertNotNull(me.getLastMinorStateDurationString());
    assertEquals(me.getLastMinorStateDurationString(), "7 seconds");

    assertNotNull(me.getLastMinorStateDurationMillis());
    assertEquals(me.getLastMinorStateDurationMillis(), Long.valueOf(7000L));

    assertNotNull(me.getTotalMinorStateDurationString());
    assertEquals(me.getTotalMinorStateDurationString(), "8 seconds");

    assertNotNull(me.getTotalMinorStateDurationMillis());
    assertEquals(me.getTotalMinorStateDurationMillis(), Long.valueOf(8000L));

    assertNotNull(me.getLastMajorStateStartTime());
    assertEquals(me.getLastMajorStateStartTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.687Z"));

    assertNotNull(me.getLastMajorStateEndTime());
    assertEquals(me.getLastMajorStateEndTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.688Z"));

    assertNotNull(me.getLastMajorStateDurationString());
    assertEquals(me.getLastMajorStateDurationString(), "9 seconds");

    assertNotNull(me.getLastMajorStateDurationMillis());
    assertEquals(me.getLastMajorStateDurationMillis(), Long.valueOf(9000L));

    assertNotNull(me.getTotalMajorStateDurationString());
    assertEquals(me.getTotalMajorStateDurationString(), "10 seconds");

    assertNotNull(me.getTotalMajorStateDurationMillis());
    assertEquals(me.getTotalMajorStateDurationMillis(), Long.valueOf(10000L));

    assertNotNull(me.getLastCriticalStateStartTime());
    assertEquals(me.getLastCriticalStateStartTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.689Z"));

    assertNotNull(me.getLastCriticalStateEndTime());
    assertEquals(me.getLastCriticalStateEndTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.690Z"));

    assertNotNull(me.getLastCriticalStateDurationString());
    assertEquals(me.getLastCriticalStateDurationString(), "11 seconds");

    assertNotNull(me.getLastCriticalStateDurationMillis());
    assertEquals(me.getLastCriticalStateDurationMillis(), Long.valueOf(11000L));

    assertNotNull(me.getTotalCriticalStateDurationString());
    assertEquals(me.getTotalCriticalStateDurationString(), "12 seconds");

    assertNotNull(me.getTotalCriticalStateDurationMillis());
    assertEquals(me.getTotalCriticalStateDurationMillis(),
         Long.valueOf(12000L));


    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());


    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(attrs);
    assertFalse(attrs.isEmpty());

    assertNotNull(attrs.get("gauge-name"));
    assertFalse(attrs.get("gauge-name").hasMultipleValues());
    assertNotNull(attrs.get("gauge-name").getStringValue());

    assertNotNull(attrs.get("resource"));
    assertFalse(attrs.get("resource").hasMultipleValues());
    assertNotNull(attrs.get("resource").getStringValue());

    assertNotNull(attrs.get("resource-type"));
    assertFalse(attrs.get("resource-type").hasMultipleValues());
    assertNotNull(attrs.get("resource-type").getStringValue());

    assertNotNull(attrs.get("severity"));
    assertFalse(attrs.get("severity").hasMultipleValues());
    assertNotNull(attrs.get("severity").getStringValue());

    assertNotNull(attrs.get("previous-severity"));
    assertFalse(attrs.get("previous-severity").hasMultipleValues());
    assertNotNull(attrs.get("previous-severity").getStringValue());

    assertNotNull(attrs.get("summary"));
    assertFalse(attrs.get("summary").hasMultipleValues());
    assertNotNull(attrs.get("summary").getStringValue());

    assertNotNull(attrs.get("error-message"));
    assertTrue(attrs.get("error-message").hasMultipleValues());
    assertNotNull(attrs.get("error-message").getStringValues());
    assertEquals(attrs.get("error-message").getStringValues().size(), 2);

    assertNotNull(attrs.get("gauge-init-time"));
    assertFalse(attrs.get("gauge-init-time").hasMultipleValues());
    assertNotNull(attrs.get("gauge-init-time").getDateValue());

    assertNotNull(attrs.get("update-time"));
    assertFalse(attrs.get("update-time").hasMultipleValues());
    assertNotNull(attrs.get("update-time").getDateValue());

    assertNotNull(attrs.get("samples-this-interval"));
    assertFalse(attrs.get("samples-this-interval").hasMultipleValues());
    assertNotNull(attrs.get("samples-this-interval").getLongValue());

    assertNotNull(attrs.get("current-severity-start-time"));
    assertFalse(attrs.get("current-severity-start-time").hasMultipleValues());
    assertNotNull(attrs.get("current-severity-start-time").getDateValue());

    assertNotNull(attrs.get("current-severity-duration"));
    assertFalse(attrs.get("current-severity-duration").hasMultipleValues());
    assertNotNull(attrs.get("current-severity-duration").getStringValue());

    assertNotNull(attrs.get("current-severity-duration-millis"));
    assertFalse(attrs.get("current-severity-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("current-severity-duration-millis").getLongValue());

    assertNotNull(attrs.get("last-normal-state-start-time"));
    assertFalse(attrs.get("last-normal-state-start-time").hasMultipleValues());
    assertNotNull(attrs.get("last-normal-state-start-time").getDateValue());

    assertNotNull(attrs.get("last-normal-state-end-time"));
    assertFalse(attrs.get("last-normal-state-end-time").hasMultipleValues());
    assertNotNull(attrs.get("last-normal-state-end-time").getDateValue());

    assertNotNull(attrs.get("last-normal-state-duration"));
    assertFalse(attrs.get("last-normal-state-duration").hasMultipleValues());
    assertNotNull(attrs.get("last-normal-state-duration").getStringValue());

    assertNotNull(attrs.get("last-normal-state-duration-millis"));
    assertFalse(attrs.get("last-normal-state-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("last-normal-state-duration-millis").
         getLongValue());

    assertNotNull(attrs.get("total-normal-state-duration"));
    assertFalse(attrs.get("total-normal-state-duration").hasMultipleValues());
    assertNotNull(attrs.get("total-normal-state-duration").getStringValue());

    assertNotNull(attrs.get("total-normal-state-duration-millis"));
    assertFalse(attrs.get("total-normal-state-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("total-normal-state-duration-millis").
         getLongValue());

    assertNotNull(attrs.get("last-warning-state-start-time"));
    assertFalse(attrs.get("last-warning-state-start-time").hasMultipleValues());
    assertNotNull(attrs.get("last-warning-state-start-time").getDateValue());

    assertNotNull(attrs.get("last-warning-state-end-time"));
    assertFalse(attrs.get("last-warning-state-end-time").hasMultipleValues());
    assertNotNull(attrs.get("last-warning-state-end-time").getDateValue());

    assertNotNull(attrs.get("last-warning-state-duration"));
    assertFalse(attrs.get("last-warning-state-duration").hasMultipleValues());
    assertNotNull(attrs.get("last-warning-state-duration").getStringValue());

    assertNotNull(attrs.get("last-warning-state-duration-millis"));
    assertFalse(attrs.get("last-warning-state-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("last-warning-state-duration-millis").
         getLongValue());

    assertNotNull(attrs.get("total-warning-state-duration"));
    assertFalse(attrs.get("total-warning-state-duration").hasMultipleValues());
    assertNotNull(attrs.get("total-warning-state-duration").getStringValue());

    assertNotNull(attrs.get("total-warning-state-duration-millis"));
    assertFalse(attrs.get("total-warning-state-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("total-warning-state-duration-millis").
         getLongValue());

    assertNotNull(attrs.get("last-minor-state-start-time"));
    assertFalse(attrs.get("last-minor-state-start-time").hasMultipleValues());
    assertNotNull(attrs.get("last-minor-state-start-time").getDateValue());

    assertNotNull(attrs.get("last-minor-state-end-time"));
    assertFalse(attrs.get("last-minor-state-end-time").hasMultipleValues());
    assertNotNull(attrs.get("last-minor-state-end-time").getDateValue());

    assertNotNull(attrs.get("last-minor-state-duration"));
    assertFalse(attrs.get("last-minor-state-duration").hasMultipleValues());
    assertNotNull(attrs.get("last-minor-state-duration").getStringValue());

    assertNotNull(attrs.get("last-minor-state-duration-millis"));
    assertFalse(attrs.get("last-minor-state-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("last-minor-state-duration-millis").
         getLongValue());

    assertNotNull(attrs.get("total-minor-state-duration"));
    assertFalse(attrs.get("total-minor-state-duration").hasMultipleValues());
    assertNotNull(attrs.get("total-minor-state-duration").getStringValue());

    assertNotNull(attrs.get("total-minor-state-duration-millis"));
    assertFalse(attrs.get("total-minor-state-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("total-minor-state-duration-millis").
         getLongValue());

    assertNotNull(attrs.get("last-major-state-start-time"));
    assertFalse(attrs.get("last-major-state-start-time").hasMultipleValues());
    assertNotNull(attrs.get("last-major-state-start-time").getDateValue());

    assertNotNull(attrs.get("last-major-state-end-time"));
    assertFalse(attrs.get("last-major-state-end-time").hasMultipleValues());
    assertNotNull(attrs.get("last-major-state-end-time").getDateValue());

    assertNotNull(attrs.get("last-major-state-duration"));
    assertFalse(attrs.get("last-major-state-duration").hasMultipleValues());
    assertNotNull(attrs.get("last-major-state-duration").getStringValue());

    assertNotNull(attrs.get("last-major-state-duration-millis"));
    assertFalse(attrs.get("last-major-state-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("last-major-state-duration-millis").
         getLongValue());

    assertNotNull(attrs.get("total-major-state-duration"));
    assertFalse(attrs.get("total-major-state-duration").hasMultipleValues());
    assertNotNull(attrs.get("total-major-state-duration").getStringValue());

    assertNotNull(attrs.get("total-major-state-duration-millis"));
    assertFalse(attrs.get("total-major-state-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("total-major-state-duration-millis").
         getLongValue());

    assertNotNull(attrs.get("last-critical-state-start-time"));
    assertFalse(attrs.get("last-critical-state-start-time").
         hasMultipleValues());
    assertNotNull(attrs.get("last-critical-state-start-time").getDateValue());

    assertNotNull(attrs.get("last-critical-state-end-time"));
    assertFalse(attrs.get("last-critical-state-end-time").hasMultipleValues());
    assertNotNull(attrs.get("last-critical-state-end-time").getDateValue());

    assertNotNull(attrs.get("last-critical-state-duration"));
    assertFalse(attrs.get("last-critical-state-duration").hasMultipleValues());
    assertNotNull(attrs.get("last-critical-state-duration").getStringValue());

    assertNotNull(attrs.get("last-critical-state-duration-millis"));
    assertFalse(attrs.get("last-critical-state-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("last-critical-state-duration-millis").
         getLongValue());

    assertNotNull(attrs.get("total-critical-state-duration"));
    assertFalse(attrs.get("total-critical-state-duration").hasMultipleValues());
    assertNotNull(attrs.get("total-critical-state-duration").getStringValue());

    assertNotNull(attrs.get("total-critical-state-duration-millis"));
    assertFalse(attrs.get("total-critical-state-duration-millis").
         hasMultipleValues());
    assertNotNull(attrs.get("total-critical-state-duration-millis").
         getLongValue());
  }



  /**
   * Provides test coverage for the constructor with a valid entry with no
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNoValues()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: cn=Test Gauge,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-gauge-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Test Gauge");

    final GaugeMonitorEntry me = new GaugeMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-gauge-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         GaugeMonitorEntry.class.getName());

    assertNull(me.getGaugeName());

    assertNull(me.getResource());

    assertNull(me.getResourceType());

    assertNull(me.getCurrentSeverity());

    assertNull(me.getPreviousSeverity());

    assertNull(me.getSummary());

    assertNotNull(me.getErrorMessages());
    assertTrue(me.getErrorMessages().isEmpty());

    assertNull(me.getInitTime());

    assertNull(me.getUpdateTime());

    assertNull(me.getSamplesThisInterval());

    assertNull(me.getCurrentSeverityStartTime());

    assertNull(me.getCurrentSeverityDurationString());

    assertNull(me.getCurrentSeverityDurationMillis());

    assertNull(me.getLastNormalStateStartTime());

    assertNull(me.getLastNormalStateEndTime());

    assertNull(me.getLastNormalStateDurationString());

    assertNull(me.getLastNormalStateDurationMillis());

    assertNull(me.getTotalNormalStateDurationString());

    assertNull(me.getTotalNormalStateDurationMillis());

    assertNull(me.getLastWarningStateStartTime());

    assertNull(me.getLastWarningStateEndTime());

    assertNull(me.getLastWarningStateDurationString());

    assertNull(me.getLastWarningStateDurationMillis());

    assertNull(me.getTotalWarningStateDurationString());

    assertNull(me.getTotalWarningStateDurationMillis());

    assertNull(me.getLastMinorStateStartTime());

    assertNull(me.getLastMinorStateEndTime());

    assertNull(me.getLastMinorStateDurationString());

    assertNull(me.getLastMinorStateDurationMillis());

    assertNull(me.getTotalMinorStateDurationString());

    assertNull(me.getTotalMinorStateDurationMillis());

    assertNull(me.getLastMajorStateStartTime());

    assertNull(me.getLastMajorStateEndTime());

    assertNull(me.getLastMajorStateDurationString());

    assertNull(me.getLastMajorStateDurationMillis());

    assertNull(me.getTotalMajorStateDurationString());

    assertNull(me.getTotalMajorStateDurationMillis());

    assertNull(me.getLastCriticalStateStartTime());

    assertNull(me.getLastCriticalStateEndTime());

    assertNull(me.getLastCriticalStateDurationString());

    assertNull(me.getLastCriticalStateDurationMillis());

    assertNull(me.getTotalCriticalStateDurationString());

    assertNull(me.getTotalCriticalStateDurationMillis());


    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());


    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(attrs);
    assertTrue(attrs.isEmpty());
  }
}
