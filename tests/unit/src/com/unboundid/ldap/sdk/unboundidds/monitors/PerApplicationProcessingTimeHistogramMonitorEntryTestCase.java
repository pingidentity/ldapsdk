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



import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the
 * PerApplicationProcessingTimeHistogramMonitorEntry class.
 */
public class PerApplicationProcessingTimeHistogramMonitorEntryTestCase
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
    Entry e = new Entry(
         "dn: cn=MyApp Processing Time Histogram,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: " +
              "ds-per-application-processing-time-histogram-monitor-entry",
         "objectClass: extensibleObject",
         "cn: MyApp Processing Time Histogram",
         "applicationName: MyApp",
         "allOpsTotalCount: 100",
         "allOpsAverageResponseTimeMillis: 1.000",
         "allOpsCount: Less than 1ms: 0",
         "allOpsCount: Between 1ms and 2ms: 0",
         "allOpsCount: Between 2ms and 3ms: 0",
         "allOpsCount: Between 3ms and 5ms: 0",
         "allOpsCount: Between 5ms and 10ms: 0",
         "allOpsCount: Between 10ms and 20ms: 0",
         "allOpsCount: Between 20ms and 30ms: 0",
         "allOpsCount: Between 30ms and 40ms: 0",
         "allOpsCount: Between 40ms and 50ms: 0",
         "allOpsCount: Between 50ms and 100ms: 0",
         "allOpsCount: Between 100ms and 1000ms: 0",
         "allOpsCount: At least 1000ms: 0",
         "allOpsPercent: Less than 1ms: 0.000%",
         "allOpsPercent: Between 1ms and 2ms: 0.000%",
         "allOpsPercent: Between 2ms and 3ms: 0.000%",
         "allOpsPercent: Between 3ms and 5ms: 0.000%",
         "allOpsPercent: Between 5ms and 10ms: 0.000%",
         "allOpsPercent: Between 10ms and 20ms: 0.000%",
         "allOpsPercent: Between 20ms and 30ms: 0.000%",
         "allOpsPercent: Between 30ms and 40ms: 0.000%",
         "allOpsPercent: Between 40ms and 50ms: 0.000%",
         "allOpsPercent: Between 50ms and 100ms: 0.000%",
         "allOpsPercent: Between 100ms and 1000ms: 0.000%",
         "allOpsPercent: At least 1000ms: 0.000%",
         "allOpsAggregatePercent: Less than 1ms: 0.0000%",
         "allOpsAggregatePercent: Between 1ms and 2ms: 0.0000%",
         "allOpsAggregatePercent: Between 2ms and 3ms: 0.0000%",
         "allOpsAggregatePercent: Between 3ms and 5ms: 0.0000%",
         "allOpsAggregatePercent: Between 5ms and 10ms: 0.0000%",
         "allOpsAggregatePercent: Between 10ms and 20ms: 0.0000%",
         "allOpsAggregatePercent: Between 20ms and 30ms: 0.0000%",
         "allOpsAggregatePercent: Between 30ms and 40ms: 0.0000%",
         "allOpsAggregatePercent: Between 40ms and 50ms: 0.0000%",
         "allOpsAggregatePercent: Between 50ms and 100ms: 0.0000%",
         "allOpsAggregatePercent: Between 100ms and 1000ms: 0.0000%",
         "allOpsAggregatePercent: At least 1000ms: 0.0000%",
         "addOpsTotalCount: 101",
         "addOpsAverageResponseTimeMillis: 1.001",
         "addOpsCount: Less than 1ms: 0",
         "addOpsCount: Between 1ms and 2ms: 0",
         "addOpsCount: Between 2ms and 3ms: 0",
         "addOpsCount: Between 3ms and 5ms: 0",
         "addOpsCount: Between 5ms and 10ms: 0",
         "addOpsCount: Between 10ms and 20ms: 0",
         "addOpsCount: Between 20ms and 30ms: 0",
         "addOpsCount: Between 30ms and 40ms: 0",
         "addOpsCount: Between 40ms and 50ms: 0",
         "addOpsCount: Between 50ms and 100ms: 0",
         "addOpsCount: Between 100ms and 1000ms: 0",
         "addOpsCount: At least 1000ms: 0",
         "addOpsPercent: Less than 1ms: 0.0000%",
         "addOpsPercent: Between 1ms and 2ms: 0.0000%",
         "addOpsPercent: Between 2ms and 3ms: 0.0000%",
         "addOpsPercent: Between 3ms and 5ms: 0.0000%",
         "addOpsPercent: Between 5ms and 10ms: 0.0000%",
         "addOpsPercent: Between 10ms and 20ms: 0.0000%",
         "addOpsPercent: Between 20ms and 30ms: 0.0000%",
         "addOpsPercent: Between 30ms and 40ms: 0.0000%",
         "addOpsPercent: Between 40ms and 50ms: 0.0000%",
         "addOpsPercent: Between 50ms and 100ms: 0.0000%",
         "addOpsPercent: Between 100ms and 1000ms: 0.0000%",
         "addOpsPercent: At least 1000ms: 0.0000%",
         "addOpsAggregatePercent: Less than 1ms: 0.0000%",
         "addOpsAggregatePercent: Between 1ms and 2ms: 0.0000%",
         "addOpsAggregatePercent: Between 2ms and 3ms: 0.0000%",
         "addOpsAggregatePercent: Between 3ms and 5ms: 0.0000%",
         "addOpsAggregatePercent: Between 5ms and 10ms: 0.0000%",
         "addOpsAggregatePercent: Between 10ms and 20ms: 0.0000%",
         "addOpsAggregatePercent: Between 20ms and 30ms: 0.0000%",
         "addOpsAggregatePercent: Between 30ms and 40ms: 0.0000%",
         "addOpsAggregatePercent: Between 40ms and 50ms: 0.0000%",
         "addOpsAggregatePercent: Between 50ms and 100ms: 0.0000%",
         "addOpsAggregatePercent: Between 100ms and 1000ms: 0.0000%",
         "addOpsAggregatePercent: At least 1000ms: 0.0000%",
         "bindOpsTotalCount: 102",
         "bindOpsAverageResponseTimeMillis: 1.002",
         "bindOpsCount: Less than 1ms: 0",
         "bindOpsCount: Between 1ms and 2ms: 0",
         "bindOpsCount: Between 2ms and 3ms: 0",
         "bindOpsCount: Between 3ms and 5ms: 0",
         "bindOpsCount: Between 5ms and 10ms: 0",
         "bindOpsCount: Between 10ms and 20ms: 0",
         "bindOpsCount: Between 20ms and 30ms: 0",
         "bindOpsCount: Between 30ms and 40ms: 0",
         "bindOpsCount: Between 40ms and 50ms: 0",
         "bindOpsCount: Between 50ms and 100ms: 0",
         "bindOpsCount: Between 100ms and 1000ms: 0",
         "bindOpsCount: At least 1000ms: 0",
         "bindOpsPercent: Less than 1ms: 0.0000%",
         "bindOpsPercent: Between 1ms and 2ms: 0.0000%",
         "bindOpsPercent: Between 2ms and 3ms: 0.0000%",
         "bindOpsPercent: Between 3ms and 5ms: 0.0000%",
         "bindOpsPercent: Between 5ms and 10ms: 0.0000%",
         "bindOpsPercent: Between 10ms and 20ms: 0.0000%",
         "bindOpsPercent: Between 20ms and 30ms: 0.0000%",
         "bindOpsPercent: Between 30ms and 40ms: 0.0000%",
         "bindOpsPercent: Between 40ms and 50ms: 0.0000%",
         "bindOpsPercent: Between 50ms and 100ms: 0.0000%",
         "bindOpsPercent: Between 100ms and 1000ms: 0.0000%",
         "bindOpsPercent: At least 1000ms: 0.0000%",
         "bindOpsAggregatePercent: Less than 1ms: 0.0000%",
         "bindOpsAggregatePercent: Between 1ms and 2ms: 0.0000%",
         "bindOpsAggregatePercent: Between 2ms and 3ms: 0.0000%",
         "bindOpsAggregatePercent: Between 3ms and 5ms: 0.0000%",
         "bindOpsAggregatePercent: Between 5ms and 10ms: 0.0000%",
         "bindOpsAggregatePercent: Between 10ms and 20ms: 0.0000%",
         "bindOpsAggregatePercent: Between 20ms and 30ms: 0.0000%",
         "bindOpsAggregatePercent: Between 30ms and 40ms: 0.0000%",
         "bindOpsAggregatePercent: Between 40ms and 50ms: 0.0000%",
         "bindOpsAggregatePercent: Between 50ms and 100ms: 0.0000%",
         "bindOpsAggregatePercent: Between 100ms and 1000ms: 0.0000%",
         "bindOpsAggregatePercent: At least 1000ms: 0.0000%",
         "compareOpsTotalCount: 103",
         "compareOpsAverageResponseTimeMillis: 1.003",
         "compareOpsCount: Less than 1ms: 0",
         "compareOpsCount: Between 1ms and 2ms: 0",
         "compareOpsCount: Between 2ms and 3ms: 0",
         "compareOpsCount: Between 3ms and 5ms: 0",
         "compareOpsCount: Between 5ms and 10ms: 0",
         "compareOpsCount: Between 10ms and 20ms: 0",
         "compareOpsCount: Between 20ms and 30ms: 0",
         "compareOpsCount: Between 30ms and 40ms: 0",
         "compareOpsCount: Between 40ms and 50ms: 0",
         "compareOpsCount: Between 50ms and 100ms: 0",
         "compareOpsCount: Between 100ms and 1000ms: 0",
         "compareOpsCount: At least 1000ms: 0",
         "compareOpsPercent: Less than 1ms: 0.0000%",
         "compareOpsPercent: Between 1ms and 2ms: 0.0000%",
         "compareOpsPercent: Between 2ms and 3ms: 0.0000%",
         "compareOpsPercent: Between 3ms and 5ms: 0.0000%",
         "compareOpsPercent: Between 5ms and 10ms: 0.0000%",
         "compareOpsPercent: Between 10ms and 20ms: 0.0000%",
         "compareOpsPercent: Between 20ms and 30ms: 0.0000%",
         "compareOpsPercent: Between 30ms and 40ms: 0.0000%",
         "compareOpsPercent: Between 40ms and 50ms: 0.0000%",
         "compareOpsPercent: Between 50ms and 100ms: 0.0000%",
         "compareOpsPercent: Between 100ms and 1000ms: 0.0000%",
         "compareOpsPercent: At least 1000ms: 0.0000%",
         "compareOpsAggregatePercent: Less than 1ms: 0.0000%",
         "compareOpsAggregatePercent: Between 1ms and 2ms: 0.0000%",
         "compareOpsAggregatePercent: Between 2ms and 3ms: 0.0000%",
         "compareOpsAggregatePercent: Between 3ms and 5ms: 0.0000%",
         "compareOpsAggregatePercent: Between 5ms and 10ms: 0.0000%",
         "compareOpsAggregatePercent: Between 10ms and 20ms: 0.0000%",
         "compareOpsAggregatePercent: Between 20ms and 30ms: 0.0000%",
         "compareOpsAggregatePercent: Between 30ms and 40ms: 0.0000%",
         "compareOpsAggregatePercent: Between 40ms and 50ms: 0.0000%",
         "compareOpsAggregatePercent: Between 50ms and 100ms: 0.0000%",
         "compareOpsAggregatePercent: Between 100ms and 1000ms: 0.0000%",
         "compareOpsAggregatePercent: At least 1000ms: 0.0000%",
         "deleteOpsTotalCount: 104",
         "deleteOpsAverageResponseTimeMillis: 1.004",
         "deleteOpsCount: Less than 1ms: 0",
         "deleteOpsCount: Between 1ms and 2ms: 0",
         "deleteOpsCount: Between 2ms and 3ms: 0",
         "deleteOpsCount: Between 3ms and 5ms: 0",
         "deleteOpsCount: Between 5ms and 10ms: 0",
         "deleteOpsCount: Between 10ms and 20ms: 0",
         "deleteOpsCount: Between 20ms and 30ms: 0",
         "deleteOpsCount: Between 30ms and 40ms: 0",
         "deleteOpsCount: Between 40ms and 50ms: 0",
         "deleteOpsCount: Between 50ms and 100ms: 0",
         "deleteOpsCount: Between 100ms and 1000ms: 0",
         "deleteOpsCount: At least 1000ms: 0",
         "deleteOpsPercent: Less than 1ms: 0.0000%",
         "deleteOpsPercent: Between 1ms and 2ms: 0.0000%",
         "deleteOpsPercent: Between 2ms and 3ms: 0.0000%",
         "deleteOpsPercent: Between 3ms and 5ms: 0.0000%",
         "deleteOpsPercent: Between 5ms and 10ms: 0.0000%",
         "deleteOpsPercent: Between 10ms and 20ms: 0.0000%",
         "deleteOpsPercent: Between 20ms and 30ms: 0.0000%",
         "deleteOpsPercent: Between 30ms and 40ms: 0.0000%",
         "deleteOpsPercent: Between 40ms and 50ms: 0.0000%",
         "deleteOpsPercent: Between 50ms and 100ms: 0.0000%",
         "deleteOpsPercent: Between 100ms and 1000ms: 0.0000%",
         "deleteOpsPercent: At least 1000ms: 0.0000%",
         "deleteOpsAggregatePercent: Less than 1ms: 0.0000%",
         "deleteOpsAggregatePercent: Between 1ms and 2ms: 0.0000%",
         "deleteOpsAggregatePercent: Between 2ms and 3ms: 0.0000%",
         "deleteOpsAggregatePercent: Between 3ms and 5ms: 0.0000%",
         "deleteOpsAggregatePercent: Between 5ms and 10ms: 0.0000%",
         "deleteOpsAggregatePercent: Between 10ms and 20ms: 0.0000%",
         "deleteOpsAggregatePercent: Between 20ms and 30ms: 0.0000%",
         "deleteOpsAggregatePercent: Between 30ms and 40ms: 0.0000%",
         "deleteOpsAggregatePercent: Between 40ms and 50ms: 0.0000%",
         "deleteOpsAggregatePercent: Between 50ms and 100ms: 0.0000%",
         "deleteOpsAggregatePercent: Between 100ms and 1000ms: 0.0000%",
         "deleteOpsAggregatePercent: At least 1000ms: 0.0000%",
         "modifyOpsTotalCount: 105",
         "modifyOpsAverageResponseTimeMillis: 1.005",
         "modifyOpsCount: Less than 1ms: 0",
         "modifyOpsCount: Between 1ms and 2ms: 0",
         "modifyOpsCount: Between 2ms and 3ms: 0",
         "modifyOpsCount: Between 3ms and 5ms: 0",
         "modifyOpsCount: Between 5ms and 10ms: 0",
         "modifyOpsCount: Between 10ms and 20ms: 0",
         "modifyOpsCount: Between 20ms and 30ms: 0",
         "modifyOpsCount: Between 30ms and 40ms: 0",
         "modifyOpsCount: Between 40ms and 50ms: 0",
         "modifyOpsCount: Between 50ms and 100ms: 0",
         "modifyOpsCount: Between 100ms and 1000ms: 0",
         "modifyOpsCount: At least 1000ms: 0",
         "modifyOpsPercent: Less than 1ms: 0.0000%",
         "modifyOpsPercent: Between 1ms and 2ms: 0.0000%",
         "modifyOpsPercent: Between 2ms and 3ms: 0.0000%",
         "modifyOpsPercent: Between 3ms and 5ms: 0.0000%",
         "modifyOpsPercent: Between 5ms and 10ms: 0.0000%",
         "modifyOpsPercent: Between 10ms and 20ms: 0.0000%",
         "modifyOpsPercent: Between 20ms and 30ms: 0.0000%",
         "modifyOpsPercent: Between 30ms and 40ms: 0.0000%",
         "modifyOpsPercent: Between 40ms and 50ms: 0.0000%",
         "modifyOpsPercent: Between 50ms and 100ms: 0.0000%",
         "modifyOpsPercent: Between 100ms and 1000ms: 0.0000%",
         "modifyOpsPercent: At least 1000ms: 0.0000%",
         "modifyOpsAggregatePercent: Less than 1ms: 0.0000%",
         "modifyOpsAggregatePercent: Between 1ms and 2ms: 0.0000%",
         "modifyOpsAggregatePercent: Between 2ms and 3ms: 0.0000%",
         "modifyOpsAggregatePercent: Between 3ms and 5ms: 0.0000%",
         "modifyOpsAggregatePercent: Between 5ms and 10ms: 0.0000%",
         "modifyOpsAggregatePercent: Between 10ms and 20ms: 0.0000%",
         "modifyOpsAggregatePercent: Between 20ms and 30ms: 0.0000%",
         "modifyOpsAggregatePercent: Between 30ms and 40ms: 0.0000%",
         "modifyOpsAggregatePercent: Between 40ms and 50ms: 0.0000%",
         "modifyOpsAggregatePercent: Between 50ms and 100ms: 0.0000%",
         "modifyOpsAggregatePercent: Between 100ms and 1000ms: 0.0000%",
         "modifyOpsAggregatePercent: At least 1000ms: 0.0000%",
         "modifyDNOpsTotalCount: 106",
         "modifyDNOpsAverageResponseTimeMillis: 1.006",
         "modifyDNOpsCount: Less than 1ms: 0",
         "modifyDNOpsCount: Between 1ms and 2ms: 0",
         "modifyDNOpsCount: Between 2ms and 3ms: 0",
         "modifyDNOpsCount: Between 3ms and 5ms: 0",
         "modifyDNOpsCount: Between 5ms and 10ms: 0",
         "modifyDNOpsCount: Between 10ms and 20ms: 0",
         "modifyDNOpsCount: Between 20ms and 30ms: 0",
         "modifyDNOpsCount: Between 30ms and 40ms: 0",
         "modifyDNOpsCount: Between 40ms and 50ms: 0",
         "modifyDNOpsCount: Between 50ms and 100ms: 0",
         "modifyDNOpsCount: Between 100ms and 1000ms: 0",
         "modifyDNOpsCount: At least 1000ms: 0",
         "modifyDNOpsPercent: Less than 1ms: 0.0000%",
         "modifyDNOpsPercent: Between 1ms and 2ms: 0.0000%",
         "modifyDNOpsPercent: Between 2ms and 3ms: 0.0000%",
         "modifyDNOpsPercent: Between 3ms and 5ms: 0.0000%",
         "modifyDNOpsPercent: Between 5ms and 10ms: 0.0000%",
         "modifyDNOpsPercent: Between 10ms and 20ms: 0.0000%",
         "modifyDNOpsPercent: Between 20ms and 30ms: 0.0000%",
         "modifyDNOpsPercent: Between 30ms and 40ms: 0.0000%",
         "modifyDNOpsPercent: Between 40ms and 50ms: 0.0000%",
         "modifyDNOpsPercent: Between 50ms and 100ms: 0.0000%",
         "modifyDNOpsPercent: Between 100ms and 1000ms: 0.0000%",
         "modifyDNOpsPercent: At least 1000ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Less than 1ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Between 1ms and 2ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Between 2ms and 3ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Between 3ms and 5ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Between 5ms and 10ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Between 10ms and 20ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Between 20ms and 30ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Between 30ms and 40ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Between 40ms and 50ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Between 50ms and 100ms: 0.0000%",
         "modifyDNOpsAggregatePercent: Between 100ms and 1000ms: 0.0000%",
         "modifyDNOpsAggregatePercent: At least 1000ms: 0.0000%",
         "searchOpsTotalCount: 107",
         "searchOpsAverageResponseTimeMillis: 1.007",
         "searchOpsCount: Less than 1ms: 0",
         "searchOpsCount: Between 1ms and 2ms: 0",
         "searchOpsCount: Between 2ms and 3ms: 0",
         "searchOpsCount: Between 3ms and 5ms: 0",
         "searchOpsCount: Between 5ms and 10ms: 0",
         "searchOpsCount: Between 10ms and 20ms: 0",
         "searchOpsCount: Between 20ms and 30ms: 0",
         "searchOpsCount: Between 30ms and 40ms: 0",
         "searchOpsCount: Between 40ms and 50ms: 0",
         "searchOpsCount: Between 50ms and 100ms: 0",
         "searchOpsCount: Between 100ms and 1000ms: 0",
         "searchOpsCount: At least 1000ms: 0",
         "searchOpsPercent: Less than 1ms: 0.0000%",
         "searchOpsPercent: Between 1ms and 2ms: 0.0000%",
         "searchOpsPercent: Between 2ms and 3ms: 0.0000%",
         "searchOpsPercent: Between 3ms and 5ms: 0.0000%",
         "searchOpsPercent: Between 5ms and 10ms: 0.0000%",
         "searchOpsPercent: Between 10ms and 20ms: 0.0000%",
         "searchOpsPercent: Between 20ms and 30ms: 0.0000%",
         "searchOpsPercent: Between 30ms and 40ms: 0.0000%",
         "searchOpsPercent: Between 40ms and 50ms: 0.0000%",
         "searchOpsPercent: Between 50ms and 100ms: 0.0000%",
         "searchOpsPercent: Between 100ms and 1000ms: 0.0000%",
         "searchOpsPercent: At least 1000ms: 0.0000%",
         "searchOpsAggregatePercent: Less than 1ms: 0.0000%",
         "searchOpsAggregatePercent: Between 1ms and 2ms: 0.0000%",
         "searchOpsAggregatePercent: Between 2ms and 3ms: 0.0000%",
         "searchOpsAggregatePercent: Between 3ms and 5ms: 0.0000%",
         "searchOpsAggregatePercent: Between 5ms and 10ms: 0.0000%",
         "searchOpsAggregatePercent: Between 10ms and 20ms: 0.0000%",
         "searchOpsAggregatePercent: Between 20ms and 30ms: 0.0000%",
         "searchOpsAggregatePercent: Between 30ms and 40ms: 0.0000%",
         "searchOpsAggregatePercent: Between 40ms and 50ms: 0.0000%",
         "searchOpsAggregatePercent: Between 50ms and 100ms: 0.0000%",
         "searchOpsAggregatePercent: Between 100ms and 1000ms: 0.0000%",
         "searchOpsAggregatePercent: At least 1000ms: 0.0000%");

    PerApplicationProcessingTimeHistogramMonitorEntry me =
         new PerApplicationProcessingTimeHistogramMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-per-application-processing-time-histogram-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         PerApplicationProcessingTimeHistogramMonitorEntry.class.getName());

    assertNotNull(me.getApplicationName());
    assertEquals(me.getApplicationName(), "MyApp");

    assertEquals(me.getAllOpsTotalCount(), Long.valueOf(100));
    assertEquals(me.getAddOpsTotalCount(), Long.valueOf(101));
    assertEquals(me.getBindOpsTotalCount(), Long.valueOf(102));
    assertEquals(me.getCompareOpsTotalCount(), Long.valueOf(103));
    assertEquals(me.getDeleteOpsTotalCount(), Long.valueOf(104));
    assertEquals(me.getModifyOpsTotalCount(), Long.valueOf(105));
    assertEquals(me.getModifyDNOpsTotalCount(), Long.valueOf(106));
    assertEquals(me.getSearchOpsTotalCount(), Long.valueOf(107));

    assertEquals(me.getAllOpsAverageResponseTimeMillis(),
                 Double.valueOf("1.000"));
    assertEquals(me.getAddOpsAverageResponseTimeMillis(),
                 Double.valueOf("1.001"));
    assertEquals(me.getBindOpsAverageResponseTimeMillis(),
                 Double.valueOf("1.002"));
    assertEquals(me.getCompareOpsAverageResponseTimeMillis(),
                 Double.valueOf("1.003"));
    assertEquals(me.getDeleteOpsAverageResponseTimeMillis(),
                 Double.valueOf("1.004"));
    assertEquals(me.getModifyOpsAverageResponseTimeMillis(),
                 Double.valueOf("1.005"));
    assertEquals(me.getModifyDNOpsAverageResponseTimeMillis(),
                 Double.valueOf("1.006"));
    assertEquals(me.getSearchOpsAverageResponseTimeMillis(),
                 Double.valueOf("1.007"));

    assertNotNull(me.getAllOpsCount());
    assertEquals(me.getAllOpsCount().size(), 12);

    assertNotNull(me.getAllOpsPercent());
    assertEquals(me.getAllOpsPercent().size(), 12);

    assertNotNull(me.getAllOpsAggregatePercent());
    assertEquals(me.getAllOpsAggregatePercent().size(), 12);

    assertNotNull(me.getAddOpsCount());
    assertEquals(me.getAddOpsCount().size(), 12);

    assertNotNull(me.getAddOpsPercent());
    assertEquals(me.getAddOpsPercent().size(), 12);

    assertNotNull(me.getAddOpsAggregatePercent());
    assertEquals(me.getAddOpsAggregatePercent().size(), 12);

    assertNotNull(me.getBindOpsCount());
    assertEquals(me.getBindOpsCount().size(), 12);

    assertNotNull(me.getBindOpsPercent());
    assertEquals(me.getBindOpsPercent().size(), 12);

    assertNotNull(me.getBindOpsAggregatePercent());
    assertEquals(me.getBindOpsAggregatePercent().size(), 12);

    assertNotNull(me.getCompareOpsCount());
    assertEquals(me.getCompareOpsCount().size(), 12);

    assertNotNull(me.getCompareOpsPercent());
    assertEquals(me.getCompareOpsPercent().size(), 12);

    assertNotNull(me.getCompareOpsAggregatePercent());
    assertEquals(me.getCompareOpsAggregatePercent().size(), 12);

    assertNotNull(me.getDeleteOpsCount());
    assertEquals(me.getDeleteOpsCount().size(), 12);

    assertNotNull(me.getDeleteOpsPercent());
    assertEquals(me.getDeleteOpsPercent().size(), 12);

    assertNotNull(me.getDeleteOpsAggregatePercent());
    assertEquals(me.getDeleteOpsAggregatePercent().size(), 12);

    assertNotNull(me.getModifyOpsCount());
    assertEquals(me.getModifyOpsCount().size(), 12);

    assertNotNull(me.getModifyOpsPercent());
    assertEquals(me.getModifyOpsPercent().size(), 12);

    assertNotNull(me.getModifyOpsAggregatePercent());
    assertEquals(me.getModifyOpsAggregatePercent().size(), 12);

    assertNotNull(me.getModifyDNOpsCount());
    assertEquals(me.getModifyDNOpsCount().size(), 12);

    assertNotNull(me.getModifyDNOpsPercent());
    assertEquals(me.getModifyDNOpsPercent().size(), 12);

    assertNotNull(me.getModifyDNOpsAggregatePercent());
    assertEquals(me.getModifyDNOpsAggregatePercent().size(), 12);

    assertNotNull(me.getSearchOpsCount());
    assertEquals(me.getSearchOpsCount().size(), 12);

    assertNotNull(me.getSearchOpsPercent());
    assertEquals(me.getSearchOpsPercent().size(), 12);

    assertNotNull(me.getSearchOpsAggregatePercent());
    assertEquals(me.getSearchOpsAggregatePercent().size(), 12);

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("allopscount-0-1"));
    assertNotNull(attrs.get("allopscount-1-2"));
    assertNotNull(attrs.get("allopscount-2-3"));
    assertNotNull(attrs.get("allopscount-3-5"));
    assertNotNull(attrs.get("allopscount-5-10"));
    assertNotNull(attrs.get("allopscount-10-20"));
    assertNotNull(attrs.get("allopscount-20-30"));
    assertNotNull(attrs.get("allopscount-30-40"));
    assertNotNull(attrs.get("allopscount-40-50"));
    assertNotNull(attrs.get("allopscount-50-100"));
    assertNotNull(attrs.get("allopscount-100-1000"));
    assertNotNull(attrs.get("allopscount-1000"));

    assertNotNull(attrs.get("allopspct-0-1"));
    assertNotNull(attrs.get("allopspct-1-2"));
    assertNotNull(attrs.get("allopspct-2-3"));
    assertNotNull(attrs.get("allopspct-3-5"));
    assertNotNull(attrs.get("allopspct-5-10"));
    assertNotNull(attrs.get("allopspct-10-20"));
    assertNotNull(attrs.get("allopspct-20-30"));
    assertNotNull(attrs.get("allopspct-30-40"));
    assertNotNull(attrs.get("allopspct-40-50"));
    assertNotNull(attrs.get("allopspct-50-100"));
    assertNotNull(attrs.get("allopspct-100-1000"));
    assertNotNull(attrs.get("allopspct-1000"));

    assertNotNull(attrs.get("allopsaggrpct-0-1"));
    assertNotNull(attrs.get("allopsaggrpct-1-2"));
    assertNotNull(attrs.get("allopsaggrpct-2-3"));
    assertNotNull(attrs.get("allopsaggrpct-3-5"));
    assertNotNull(attrs.get("allopsaggrpct-5-10"));
    assertNotNull(attrs.get("allopsaggrpct-10-20"));
    assertNotNull(attrs.get("allopsaggrpct-20-30"));
    assertNotNull(attrs.get("allopsaggrpct-30-40"));
    assertNotNull(attrs.get("allopsaggrpct-40-50"));
    assertNotNull(attrs.get("allopsaggrpct-50-100"));
    assertNotNull(attrs.get("allopsaggrpct-100-1000"));

    assertNotNull(attrs.get("addopscount-0-1"));
    assertNotNull(attrs.get("addopscount-1-2"));
    assertNotNull(attrs.get("addopscount-2-3"));
    assertNotNull(attrs.get("addopscount-3-5"));
    assertNotNull(attrs.get("addopscount-5-10"));
    assertNotNull(attrs.get("addopscount-10-20"));
    assertNotNull(attrs.get("addopscount-20-30"));
    assertNotNull(attrs.get("addopscount-30-40"));
    assertNotNull(attrs.get("addopscount-40-50"));
    assertNotNull(attrs.get("addopscount-50-100"));
    assertNotNull(attrs.get("addopscount-100-1000"));
    assertNotNull(attrs.get("addopscount-1000"));

    assertNotNull(attrs.get("addopspct-0-1"));
    assertNotNull(attrs.get("addopspct-1-2"));
    assertNotNull(attrs.get("addopspct-2-3"));
    assertNotNull(attrs.get("addopspct-3-5"));
    assertNotNull(attrs.get("addopspct-5-10"));
    assertNotNull(attrs.get("addopspct-10-20"));
    assertNotNull(attrs.get("addopspct-20-30"));
    assertNotNull(attrs.get("addopspct-30-40"));
    assertNotNull(attrs.get("addopspct-40-50"));
    assertNotNull(attrs.get("addopspct-50-100"));
    assertNotNull(attrs.get("addopspct-100-1000"));
    assertNotNull(attrs.get("addopspct-1000"));

    assertNotNull(attrs.get("addopsaggrpct-0-1"));
    assertNotNull(attrs.get("addopsaggrpct-1-2"));
    assertNotNull(attrs.get("addopsaggrpct-2-3"));
    assertNotNull(attrs.get("addopsaggrpct-3-5"));
    assertNotNull(attrs.get("addopsaggrpct-5-10"));
    assertNotNull(attrs.get("addopsaggrpct-10-20"));
    assertNotNull(attrs.get("addopsaggrpct-20-30"));
    assertNotNull(attrs.get("addopsaggrpct-30-40"));
    assertNotNull(attrs.get("addopsaggrpct-40-50"));
    assertNotNull(attrs.get("addopsaggrpct-50-100"));
    assertNotNull(attrs.get("addopsaggrpct-100-1000"));

    assertNotNull(attrs.get("bindopscount-0-1"));
    assertNotNull(attrs.get("bindopscount-1-2"));
    assertNotNull(attrs.get("bindopscount-2-3"));
    assertNotNull(attrs.get("bindopscount-3-5"));
    assertNotNull(attrs.get("bindopscount-5-10"));
    assertNotNull(attrs.get("bindopscount-10-20"));
    assertNotNull(attrs.get("bindopscount-20-30"));
    assertNotNull(attrs.get("bindopscount-30-40"));
    assertNotNull(attrs.get("bindopscount-40-50"));
    assertNotNull(attrs.get("bindopscount-50-100"));
    assertNotNull(attrs.get("bindopscount-100-1000"));
    assertNotNull(attrs.get("bindopscount-1000"));

    assertNotNull(attrs.get("bindopspct-0-1"));
    assertNotNull(attrs.get("bindopspct-1-2"));
    assertNotNull(attrs.get("bindopspct-2-3"));
    assertNotNull(attrs.get("bindopspct-3-5"));
    assertNotNull(attrs.get("bindopspct-5-10"));
    assertNotNull(attrs.get("bindopspct-10-20"));
    assertNotNull(attrs.get("bindopspct-20-30"));
    assertNotNull(attrs.get("bindopspct-30-40"));
    assertNotNull(attrs.get("bindopspct-40-50"));
    assertNotNull(attrs.get("bindopspct-50-100"));
    assertNotNull(attrs.get("bindopspct-100-1000"));
    assertNotNull(attrs.get("bindopspct-1000"));

    assertNotNull(attrs.get("bindopsaggrpct-0-1"));
    assertNotNull(attrs.get("bindopsaggrpct-1-2"));
    assertNotNull(attrs.get("bindopsaggrpct-2-3"));
    assertNotNull(attrs.get("bindopsaggrpct-3-5"));
    assertNotNull(attrs.get("bindopsaggrpct-5-10"));
    assertNotNull(attrs.get("bindopsaggrpct-10-20"));
    assertNotNull(attrs.get("bindopsaggrpct-20-30"));
    assertNotNull(attrs.get("bindopsaggrpct-30-40"));
    assertNotNull(attrs.get("bindopsaggrpct-40-50"));
    assertNotNull(attrs.get("bindopsaggrpct-50-100"));
    assertNotNull(attrs.get("bindopsaggrpct-100-1000"));

    assertNotNull(attrs.get("compareopscount-0-1"));
    assertNotNull(attrs.get("compareopscount-1-2"));
    assertNotNull(attrs.get("compareopscount-2-3"));
    assertNotNull(attrs.get("compareopscount-3-5"));
    assertNotNull(attrs.get("compareopscount-5-10"));
    assertNotNull(attrs.get("compareopscount-10-20"));
    assertNotNull(attrs.get("compareopscount-20-30"));
    assertNotNull(attrs.get("compareopscount-30-40"));
    assertNotNull(attrs.get("compareopscount-40-50"));
    assertNotNull(attrs.get("compareopscount-50-100"));
    assertNotNull(attrs.get("compareopscount-100-1000"));
    assertNotNull(attrs.get("compareopscount-1000"));

    assertNotNull(attrs.get("compareopspct-0-1"));
    assertNotNull(attrs.get("compareopspct-1-2"));
    assertNotNull(attrs.get("compareopspct-2-3"));
    assertNotNull(attrs.get("compareopspct-3-5"));
    assertNotNull(attrs.get("compareopspct-5-10"));
    assertNotNull(attrs.get("compareopspct-10-20"));
    assertNotNull(attrs.get("compareopspct-20-30"));
    assertNotNull(attrs.get("compareopspct-30-40"));
    assertNotNull(attrs.get("compareopspct-40-50"));
    assertNotNull(attrs.get("compareopspct-50-100"));
    assertNotNull(attrs.get("compareopspct-100-1000"));
    assertNotNull(attrs.get("compareopspct-1000"));

    assertNotNull(attrs.get("compareopsaggrpct-0-1"));
    assertNotNull(attrs.get("compareopsaggrpct-1-2"));
    assertNotNull(attrs.get("compareopsaggrpct-2-3"));
    assertNotNull(attrs.get("compareopsaggrpct-3-5"));
    assertNotNull(attrs.get("compareopsaggrpct-5-10"));
    assertNotNull(attrs.get("compareopsaggrpct-10-20"));
    assertNotNull(attrs.get("compareopsaggrpct-20-30"));
    assertNotNull(attrs.get("compareopsaggrpct-30-40"));
    assertNotNull(attrs.get("compareopsaggrpct-40-50"));
    assertNotNull(attrs.get("compareopsaggrpct-50-100"));
    assertNotNull(attrs.get("compareopsaggrpct-100-1000"));

    assertNotNull(attrs.get("deleteopscount-0-1"));
    assertNotNull(attrs.get("deleteopscount-1-2"));
    assertNotNull(attrs.get("deleteopscount-2-3"));
    assertNotNull(attrs.get("deleteopscount-3-5"));
    assertNotNull(attrs.get("deleteopscount-5-10"));
    assertNotNull(attrs.get("deleteopscount-10-20"));
    assertNotNull(attrs.get("deleteopscount-20-30"));
    assertNotNull(attrs.get("deleteopscount-30-40"));
    assertNotNull(attrs.get("deleteopscount-40-50"));
    assertNotNull(attrs.get("deleteopscount-50-100"));
    assertNotNull(attrs.get("deleteopscount-100-1000"));
    assertNotNull(attrs.get("deleteopscount-1000"));

    assertNotNull(attrs.get("deleteopspct-0-1"));
    assertNotNull(attrs.get("deleteopspct-1-2"));
    assertNotNull(attrs.get("deleteopspct-2-3"));
    assertNotNull(attrs.get("deleteopspct-3-5"));
    assertNotNull(attrs.get("deleteopspct-5-10"));
    assertNotNull(attrs.get("deleteopspct-10-20"));
    assertNotNull(attrs.get("deleteopspct-20-30"));
    assertNotNull(attrs.get("deleteopspct-30-40"));
    assertNotNull(attrs.get("deleteopspct-40-50"));
    assertNotNull(attrs.get("deleteopspct-50-100"));
    assertNotNull(attrs.get("deleteopspct-100-1000"));
    assertNotNull(attrs.get("deleteopspct-1000"));

    assertNotNull(attrs.get("deleteopsaggrpct-0-1"));
    assertNotNull(attrs.get("deleteopsaggrpct-1-2"));
    assertNotNull(attrs.get("deleteopsaggrpct-2-3"));
    assertNotNull(attrs.get("deleteopsaggrpct-3-5"));
    assertNotNull(attrs.get("deleteopsaggrpct-5-10"));
    assertNotNull(attrs.get("deleteopsaggrpct-10-20"));
    assertNotNull(attrs.get("deleteopsaggrpct-20-30"));
    assertNotNull(attrs.get("deleteopsaggrpct-30-40"));
    assertNotNull(attrs.get("deleteopsaggrpct-40-50"));
    assertNotNull(attrs.get("deleteopsaggrpct-50-100"));
    assertNotNull(attrs.get("deleteopsaggrpct-100-1000"));

    assertNotNull(attrs.get("modifyopscount-0-1"));
    assertNotNull(attrs.get("modifyopscount-1-2"));
    assertNotNull(attrs.get("modifyopscount-2-3"));
    assertNotNull(attrs.get("modifyopscount-3-5"));
    assertNotNull(attrs.get("modifyopscount-5-10"));
    assertNotNull(attrs.get("modifyopscount-10-20"));
    assertNotNull(attrs.get("modifyopscount-20-30"));
    assertNotNull(attrs.get("modifyopscount-30-40"));
    assertNotNull(attrs.get("modifyopscount-40-50"));
    assertNotNull(attrs.get("modifyopscount-50-100"));
    assertNotNull(attrs.get("modifyopscount-100-1000"));
    assertNotNull(attrs.get("modifyopscount-1000"));

    assertNotNull(attrs.get("modifyopspct-0-1"));
    assertNotNull(attrs.get("modifyopspct-1-2"));
    assertNotNull(attrs.get("modifyopspct-2-3"));
    assertNotNull(attrs.get("modifyopspct-3-5"));
    assertNotNull(attrs.get("modifyopspct-5-10"));
    assertNotNull(attrs.get("modifyopspct-10-20"));
    assertNotNull(attrs.get("modifyopspct-20-30"));
    assertNotNull(attrs.get("modifyopspct-30-40"));
    assertNotNull(attrs.get("modifyopspct-40-50"));
    assertNotNull(attrs.get("modifyopspct-50-100"));
    assertNotNull(attrs.get("modifyopspct-100-1000"));
    assertNotNull(attrs.get("modifyopspct-1000"));

    assertNotNull(attrs.get("modifyopsaggrpct-0-1"));
    assertNotNull(attrs.get("modifyopsaggrpct-1-2"));
    assertNotNull(attrs.get("modifyopsaggrpct-2-3"));
    assertNotNull(attrs.get("modifyopsaggrpct-3-5"));
    assertNotNull(attrs.get("modifyopsaggrpct-5-10"));
    assertNotNull(attrs.get("modifyopsaggrpct-10-20"));
    assertNotNull(attrs.get("modifyopsaggrpct-20-30"));
    assertNotNull(attrs.get("modifyopsaggrpct-30-40"));
    assertNotNull(attrs.get("modifyopsaggrpct-40-50"));
    assertNotNull(attrs.get("modifyopsaggrpct-50-100"));
    assertNotNull(attrs.get("modifyopsaggrpct-100-1000"));

    assertNotNull(attrs.get("modifydnopscount-0-1"));
    assertNotNull(attrs.get("modifydnopscount-1-2"));
    assertNotNull(attrs.get("modifydnopscount-2-3"));
    assertNotNull(attrs.get("modifydnopscount-3-5"));
    assertNotNull(attrs.get("modifydnopscount-5-10"));
    assertNotNull(attrs.get("modifydnopscount-10-20"));
    assertNotNull(attrs.get("modifydnopscount-20-30"));
    assertNotNull(attrs.get("modifydnopscount-30-40"));
    assertNotNull(attrs.get("modifydnopscount-40-50"));
    assertNotNull(attrs.get("modifydnopscount-50-100"));
    assertNotNull(attrs.get("modifydnopscount-100-1000"));
    assertNotNull(attrs.get("modifydnopscount-1000"));

    assertNotNull(attrs.get("modifydnopspct-0-1"));
    assertNotNull(attrs.get("modifydnopspct-1-2"));
    assertNotNull(attrs.get("modifydnopspct-2-3"));
    assertNotNull(attrs.get("modifydnopspct-3-5"));
    assertNotNull(attrs.get("modifydnopspct-5-10"));
    assertNotNull(attrs.get("modifydnopspct-10-20"));
    assertNotNull(attrs.get("modifydnopspct-20-30"));
    assertNotNull(attrs.get("modifydnopspct-30-40"));
    assertNotNull(attrs.get("modifydnopspct-40-50"));
    assertNotNull(attrs.get("modifydnopspct-50-100"));
    assertNotNull(attrs.get("modifydnopspct-100-1000"));
    assertNotNull(attrs.get("modifydnopspct-1000"));

    assertNotNull(attrs.get("modifydnopsaggrpct-0-1"));
    assertNotNull(attrs.get("modifydnopsaggrpct-1-2"));
    assertNotNull(attrs.get("modifydnopsaggrpct-2-3"));
    assertNotNull(attrs.get("modifydnopsaggrpct-3-5"));
    assertNotNull(attrs.get("modifydnopsaggrpct-5-10"));
    assertNotNull(attrs.get("modifydnopsaggrpct-10-20"));
    assertNotNull(attrs.get("modifydnopsaggrpct-20-30"));
    assertNotNull(attrs.get("modifydnopsaggrpct-30-40"));
    assertNotNull(attrs.get("modifydnopsaggrpct-40-50"));
    assertNotNull(attrs.get("modifydnopsaggrpct-50-100"));
    assertNotNull(attrs.get("modifydnopsaggrpct-100-1000"));

    assertNotNull(attrs.get("searchopscount-0-1"));
    assertNotNull(attrs.get("searchopscount-1-2"));
    assertNotNull(attrs.get("searchopscount-2-3"));
    assertNotNull(attrs.get("searchopscount-3-5"));
    assertNotNull(attrs.get("searchopscount-5-10"));
    assertNotNull(attrs.get("searchopscount-10-20"));
    assertNotNull(attrs.get("searchopscount-20-30"));
    assertNotNull(attrs.get("searchopscount-30-40"));
    assertNotNull(attrs.get("searchopscount-40-50"));
    assertNotNull(attrs.get("searchopscount-50-100"));
    assertNotNull(attrs.get("searchopscount-100-1000"));
    assertNotNull(attrs.get("searchopscount-1000"));

    assertNotNull(attrs.get("searchopspct-0-1"));
    assertNotNull(attrs.get("searchopspct-1-2"));
    assertNotNull(attrs.get("searchopspct-2-3"));
    assertNotNull(attrs.get("searchopspct-3-5"));
    assertNotNull(attrs.get("searchopspct-5-10"));
    assertNotNull(attrs.get("searchopspct-10-20"));
    assertNotNull(attrs.get("searchopspct-20-30"));
    assertNotNull(attrs.get("searchopspct-30-40"));
    assertNotNull(attrs.get("searchopspct-40-50"));
    assertNotNull(attrs.get("searchopspct-50-100"));
    assertNotNull(attrs.get("searchopspct-100-1000"));
    assertNotNull(attrs.get("searchopspct-1000"));

    assertNotNull(attrs.get("searchopsaggrpct-0-1"));
    assertNotNull(attrs.get("searchopsaggrpct-1-2"));
    assertNotNull(attrs.get("searchopsaggrpct-2-3"));
    assertNotNull(attrs.get("searchopsaggrpct-3-5"));
    assertNotNull(attrs.get("searchopsaggrpct-5-10"));
    assertNotNull(attrs.get("searchopsaggrpct-10-20"));
    assertNotNull(attrs.get("searchopsaggrpct-20-30"));
    assertNotNull(attrs.get("searchopsaggrpct-30-40"));
    assertNotNull(attrs.get("searchopsaggrpct-40-50"));
    assertNotNull(attrs.get("searchopsaggrpct-50-100"));
    assertNotNull(attrs.get("searchopsaggrpct-100-1000"));
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
    Entry e = new Entry(
         "dn: cn=MyApp Processing Time Histogram,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: " +
              "ds-per-application-processing-time-histogram-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Processing Time Histogram");

    PerApplicationProcessingTimeHistogramMonitorEntry me =
         new PerApplicationProcessingTimeHistogramMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-per-application-processing-time-histogram-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         PerApplicationProcessingTimeHistogramMonitorEntry.class.getName());

    assertNull(me.getApplicationName());

    assertNull(me.getAllOpsTotalCount());

    assertNull(me.getAllOpsAverageResponseTimeMillis());

    assertNotNull(me.getAllOpsCount());
    assertEquals(me.getAllOpsCount().size(), 0);

    assertNotNull(me.getAllOpsPercent());
    assertEquals(me.getAllOpsPercent().size(), 0);

    assertNotNull(me.getAllOpsAggregatePercent());
    assertEquals(me.getAllOpsAggregatePercent().size(), 0);

    assertNull(me.getAddOpsTotalCount());

    assertNull(me.getAddOpsAverageResponseTimeMillis());

    assertNotNull(me.getAddOpsCount());
    assertEquals(me.getAddOpsCount().size(), 0);

    assertNotNull(me.getAddOpsPercent());
    assertEquals(me.getAddOpsPercent().size(), 0);

    assertNotNull(me.getAddOpsAggregatePercent());
    assertEquals(me.getAddOpsAggregatePercent().size(), 0);

    assertNull(me.getBindOpsTotalCount());

    assertNull(me.getBindOpsAverageResponseTimeMillis());

    assertNotNull(me.getBindOpsCount());
    assertEquals(me.getBindOpsCount().size(), 0);

    assertNotNull(me.getBindOpsPercent());
    assertEquals(me.getBindOpsPercent().size(), 0);

    assertNotNull(me.getBindOpsAggregatePercent());
    assertEquals(me.getBindOpsAggregatePercent().size(), 0);

    assertNull(me.getCompareOpsTotalCount());

    assertNull(me.getCompareOpsAverageResponseTimeMillis());

    assertNotNull(me.getCompareOpsCount());
    assertEquals(me.getCompareOpsCount().size(), 0);

    assertNotNull(me.getCompareOpsPercent());
    assertEquals(me.getCompareOpsPercent().size(), 0);

    assertNotNull(me.getCompareOpsAggregatePercent());
    assertEquals(me.getCompareOpsAggregatePercent().size(), 0);

    assertNull(me.getDeleteOpsTotalCount());

    assertNull(me.getDeleteOpsAverageResponseTimeMillis());

    assertNotNull(me.getDeleteOpsCount());
    assertEquals(me.getDeleteOpsCount().size(), 0);

    assertNotNull(me.getDeleteOpsPercent());
    assertEquals(me.getDeleteOpsPercent().size(), 0);

    assertNotNull(me.getDeleteOpsAggregatePercent());
    assertEquals(me.getDeleteOpsAggregatePercent().size(), 0);

    assertNull(me.getModifyOpsTotalCount());

    assertNull(me.getModifyOpsAverageResponseTimeMillis());

    assertNotNull(me.getModifyOpsCount());
    assertEquals(me.getModifyOpsCount().size(), 0);

    assertNotNull(me.getModifyOpsPercent());
    assertEquals(me.getModifyOpsPercent().size(), 0);

    assertNotNull(me.getModifyOpsAggregatePercent());
    assertEquals(me.getModifyOpsAggregatePercent().size(), 0);

    assertNull(me.getModifyDNOpsTotalCount());

    assertNull(me.getModifyDNOpsAverageResponseTimeMillis());

    assertNotNull(me.getModifyDNOpsCount());
    assertEquals(me.getModifyDNOpsCount().size(), 0);

    assertNotNull(me.getModifyDNOpsPercent());
    assertEquals(me.getModifyDNOpsPercent().size(), 0);

    assertNotNull(me.getModifyDNOpsAggregatePercent());
    assertEquals(me.getModifyDNOpsAggregatePercent().size(), 0);

    assertNull(me.getSearchOpsTotalCount());

    assertNull(me.getSearchOpsAverageResponseTimeMillis());

    assertNotNull(me.getSearchOpsCount());
    assertEquals(me.getSearchOpsCount().size(), 0);

    assertNotNull(me.getSearchOpsPercent());
    assertEquals(me.getSearchOpsPercent().size(), 0);

    assertNotNull(me.getSearchOpsAggregatePercent());
    assertEquals(me.getSearchOpsAggregatePercent().size(), 0);
  }
}
