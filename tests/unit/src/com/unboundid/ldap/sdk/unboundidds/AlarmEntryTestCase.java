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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the alarm entry class.
 */
public final class AlarmEntryTestCase
     extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an entry that doesn't have any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyEntry()
         throws Exception
  {
    final AlarmEntry e = new AlarmEntry(new Entry("cn=Empty Entry,cn=alarms"));

    assertNull(e.getAlarmID());

    assertNull(e.getAlarmCondition());

    assertNull(e.getCurrentAlarmSeverity());

    assertNull(e.getPreviousAlarmSeverity());

    assertNull(e.getAlarmStartTime());

    assertNull(e.getAlarmSpecificResource());

    assertNull(e.getAlarmSpecificResourceType());

    assertNull(e.getAlarmDetails());

    assertNull(e.getAlarmAdditionalText());

    assertNull(e.getAlarmLastNormalTime());

    assertNull(e.getAlarmLastWarningTime());

    assertNull(e.getAlarmLastMinorTime());

    assertNull(e.getAlarmLastMajorTime());

    assertNull(e.getAlarmLastCriticalTime());

    assertNull(e.getAlarmLastIndeterminateTime());

    assertNull(e.getAlarmTotalDurationNormalMillis());

    assertNull(e.getAlarmTotalDurationWarningMillis());

    assertNull(e.getAlarmTotalDurationMinorMillis());

    assertNull(e.getAlarmTotalDurationMajorMillis());

    assertNull(e.getAlarmTotalDurationCriticalMillis());

    assertNull(e.getAlarmTotalDurationIndeterminateMillis());

    assertNull(e.getAlarmEventType());

    assertNull(e.getAlarmProbableCause());
  }



  /**
   * Tests the behavior with an entry that has values for all of the attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteEntry()
         throws Exception
  {
    final AlarmEntry e = new AlarmEntry(new Entry(
         "dn: ds-alarm-id=Example Alarm,cn=alarms",
         "objectClass: top",
         "objectClass: ds-admin-alarm",
         "ds-alarm-id: Example Alarm",
         "ds-alarm-condition: Example Condition",
         "ds-alarm-severity: NORMAL",
         "ds-alarm-previous-severity: WARNING",
         "ds-alarm-start-time: 20140101000000.000Z",
         "ds-alarm-specific-resource: Example Specific Resource",
         "ds-alarm-specific-resource-type: Example Specific Resource Type",
         "ds-alarm-details: Example Details",
         "ds-alarm-additional-text: Example Additional Text",
         "ds-alarm-normal-last-time: 20140101000000.001Z",
         "ds-alarm-warning-last-time: 20140101000000.002Z",
         "ds-alarm-minor-last-time: 20140101000000.003Z",
         "ds-alarm-major-last-time: 20140101000000.004Z",
         "ds-alarm-critical-last-time: 20140101000000.005Z",
         "ds-alarm-indeterminate-last-time: 20140101000000.006Z",
         "ds-alarm-normal-total-duration-millis: 1",
         "ds-alarm-warning-total-duration-millis: 2",
         "ds-alarm-minor-total-duration-millis: 3",
         "ds-alarm-major-total-duration-millis: 4",
         "ds-alarm-critical-total-duration-millis: 5",
         "ds-alarm-indeterminate-total-duration-millis: 6",
         "ds-alarm-event-type: 7",
         "ds-alarm-probable-cause: 8"));

    assertNotNull(e.getAlarmID());
    assertEquals(e.getAlarmID(), "Example Alarm");

    assertNotNull(e.getAlarmCondition());
    assertEquals(e.getAlarmCondition(), "Example Condition");

    assertNotNull(e.getCurrentAlarmSeverity());
    assertEquals(e.getCurrentAlarmSeverity(), AlarmSeverity.NORMAL);

    assertNotNull(e.getPreviousAlarmSeverity());
    assertEquals(e.getPreviousAlarmSeverity(), AlarmSeverity.WARNING);

    assertNotNull(e.getAlarmStartTime());
    assertEquals(e.getAlarmStartTime(),
         StaticUtils.decodeGeneralizedTime("20140101000000.000Z"));

    assertNotNull(e.getAlarmSpecificResource());
    assertEquals(e.getAlarmSpecificResource(), "Example Specific Resource");

    assertNotNull(e.getAlarmSpecificResourceType());
    assertEquals(e.getAlarmSpecificResourceType(),
         "Example Specific Resource Type");

    assertNotNull(e.getAlarmDetails());
    assertEquals(e.getAlarmDetails(), "Example Details");

    assertNotNull(e.getAlarmAdditionalText());
    assertEquals(e.getAlarmAdditionalText(), "Example Additional Text");

    assertNotNull(e.getAlarmLastNormalTime());
    assertEquals(e.getAlarmLastNormalTime(),
         StaticUtils.decodeGeneralizedTime("20140101000000.001Z"));

    assertNotNull(e.getAlarmLastWarningTime());
    assertEquals(e.getAlarmLastWarningTime(),
         StaticUtils.decodeGeneralizedTime("20140101000000.002Z"));

    assertNotNull(e.getAlarmLastMinorTime());
    assertEquals(e.getAlarmLastMinorTime(),
         StaticUtils.decodeGeneralizedTime("20140101000000.003Z"));

    assertNotNull(e.getAlarmLastMajorTime());
    assertEquals(e.getAlarmLastMajorTime(),
         StaticUtils.decodeGeneralizedTime("20140101000000.004Z"));

    assertNotNull(e.getAlarmLastCriticalTime());
    assertEquals(e.getAlarmLastCriticalTime(),
         StaticUtils.decodeGeneralizedTime("20140101000000.005Z"));

    assertNotNull(e.getAlarmLastIndeterminateTime());
    assertEquals(e.getAlarmLastIndeterminateTime(),
         StaticUtils.decodeGeneralizedTime("20140101000000.006Z"));

    assertNotNull(e.getAlarmTotalDurationNormalMillis());
    assertEquals(e.getAlarmTotalDurationNormalMillis().longValue(), 1L);

    assertNotNull(e.getAlarmTotalDurationWarningMillis());
    assertEquals(e.getAlarmTotalDurationWarningMillis().longValue(), 2L);

    assertNotNull(e.getAlarmTotalDurationMinorMillis());
    assertEquals(e.getAlarmTotalDurationMinorMillis().longValue(), 3L);

    assertNotNull(e.getAlarmTotalDurationMajorMillis());
    assertEquals(e.getAlarmTotalDurationMajorMillis().longValue(), 4L);

    assertNotNull(e.getAlarmTotalDurationCriticalMillis());
    assertEquals(e.getAlarmTotalDurationCriticalMillis().longValue(), 5L);

    assertNotNull(e.getAlarmTotalDurationIndeterminateMillis());
    assertEquals(e.getAlarmTotalDurationIndeterminateMillis().longValue(), 6L);

    assertNotNull(e.getAlarmEventType());
    assertEquals(e.getAlarmEventType().intValue(), 7);

    assertNotNull(e.getAlarmProbableCause());
    assertEquals(e.getAlarmProbableCause().intValue(), 8);
  }



  /**
   * Tests the behavior with an entry that has values for all of the attributes,
   * but many of those values are malformed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteEntryMalformedValues()
         throws Exception
  {
    final AlarmEntry e = new AlarmEntry(new Entry(
         "dn: ds-alarm-id=Example Alarm,cn=alarms",
         "objectClass: top",
         "objectClass: ds-admin-alarm",
         "ds-alarm-id: Example Alarm",
         "ds-alarm-condition: Example Condition",
         "ds-alarm-severity: malformed",
         "ds-alarm-previous-severity: malformed",
         "ds-alarm-start-time: malformed",
         "ds-alarm-specific-resource: Example Specific Resource",
         "ds-alarm-specific-resource-type: Example Specific Resource Type",
         "ds-alarm-details: Example Details",
         "ds-alarm-additional-text: Example Additional Text",
         "ds-alarm-normal-last-time: malformed",
         "ds-alarm-warning-last-time: malformed",
         "ds-alarm-minor-last-time: malformed",
         "ds-alarm-major-last-time: malformed",
         "ds-alarm-critical-last-time: malformed",
         "ds-alarm-indeterminate-last-time: malformed",
         "ds-alarm-normal-total-duration-millis: malformed",
         "ds-alarm-warning-total-duration-millis: malformed",
         "ds-alarm-minor-total-duration-millis: malformed",
         "ds-alarm-major-total-duration-millis: malformed",
         "ds-alarm-critical-total-duration-millis: malformed",
         "ds-alarm-indeterminate-total-duration-millis: malformed",
         "ds-alarm-event-type: malformed",
         "ds-alarm-probable-cause: malformed"));

    assertNotNull(e.getAlarmID());
    assertEquals(e.getAlarmID(), "Example Alarm");

    assertNotNull(e.getAlarmCondition());
    assertEquals(e.getAlarmCondition(), "Example Condition");

    assertNull(e.getCurrentAlarmSeverity());

    assertNull(e.getPreviousAlarmSeverity());

    assertNull(e.getAlarmStartTime());

    assertNotNull(e.getAlarmSpecificResource());
    assertEquals(e.getAlarmSpecificResource(), "Example Specific Resource");

    assertNotNull(e.getAlarmSpecificResourceType());
    assertEquals(e.getAlarmSpecificResourceType(),
         "Example Specific Resource Type");

    assertNotNull(e.getAlarmDetails());
    assertEquals(e.getAlarmDetails(), "Example Details");

    assertNotNull(e.getAlarmAdditionalText());
    assertEquals(e.getAlarmAdditionalText(), "Example Additional Text");

    assertNull(e.getAlarmLastNormalTime());

    assertNull(e.getAlarmLastWarningTime());

    assertNull(e.getAlarmLastMinorTime());

    assertNull(e.getAlarmLastMajorTime());

    assertNull(e.getAlarmLastCriticalTime());

    assertNull(e.getAlarmLastIndeterminateTime());

    assertNull(e.getAlarmTotalDurationNormalMillis());

    assertNull(e.getAlarmTotalDurationWarningMillis());

    assertNull(e.getAlarmTotalDurationMinorMillis());

    assertNull(e.getAlarmTotalDurationMajorMillis());

    assertNull(e.getAlarmTotalDurationCriticalMillis());

    assertNull(e.getAlarmTotalDurationIndeterminateMillis());

    assertNull(e.getAlarmEventType());

    assertNull(e.getAlarmProbableCause());
  }
}
