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


import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the
 * HostSystemRecentCPUAndMemoryMonitorEntry class.
 */
public class HostSystemRecentCPUAndMemoryMonitorEntryTestCase
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
         "dn: cn=Host System Recent CPU and Memory,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-host-system-cpu-memory-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Host System Recent CPU and Memory",
         "timestamp: 20140102030405.678Z",
         "recent-cpu-user: 12.34",
         "recent-cpu-system: 5.67",
         "recent-cpu-iowait: 8.90",
         "recent-cpu-used: 26.91",
         "recent-cpu-idle: 73.09",
         "total-memory-gb: 123.45",
         "recent-memory-free-gb: 67.89",
         "recent-memory-pct-free: 54.99");

    final HostSystemRecentCPUAndMemoryMonitorEntry me =
         new HostSystemRecentCPUAndMemoryMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
         "ds-host-system-cpu-memory-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         HostSystemRecentCPUAndMemoryMonitorEntry.class.getName());

    assertNotNull(me.getUpdateTime());
    assertEquals(me.getUpdateTime(),
         StaticUtils.decodeGeneralizedTime("20140102030405.678Z"));

    assertNotNull(me.getRecentCPUTotalBusyPercent());
    assertEquals(me.getRecentCPUTotalBusyPercent(), Double.valueOf("26.91"));

    assertNotNull(me.getRecentCPUUserPercent());
    assertEquals(me.getRecentCPUUserPercent(), Double.valueOf("12.34"));

    assertNotNull(me.getRecentCPUSystemPercent());
    assertEquals(me.getRecentCPUSystemPercent(), Double.valueOf("5.67"));

    assertNotNull(me.getRecentCPUIOWaitPercent());
    assertEquals(me.getRecentCPUIOWaitPercent(), Double.valueOf("8.90"));

    assertNotNull(me.getRecentCPUIdlePercent());
    assertEquals(me.getRecentCPUIdlePercent(), Double.valueOf("73.09"));

    assertNotNull(me.getTotalSystemMemoryGB());
    assertEquals(me.getTotalSystemMemoryGB(), Double.valueOf("123.45"));

    assertNotNull(me.getRecentSystemMemoryFreeGB());
    assertEquals(me.getRecentSystemMemoryFreeGB(), Double.valueOf("67.89"));

    assertNotNull(me.getRecentSystemMemoryPercentFree());
    assertEquals(me.getRecentSystemMemoryPercentFree(),
         Double.valueOf("54.99"));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());


    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(attrs);
    assertFalse(attrs.isEmpty());

    assertNotNull(attrs.get("timestamp"));
    assertFalse(attrs.get("timestamp").hasMultipleValues());
    assertNotNull(attrs.get("timestamp").getDateValue());

    assertNotNull(attrs.get("recent-cpu-user"));
    assertFalse(attrs.get("recent-cpu-user").hasMultipleValues());
    assertNotNull(attrs.get("recent-cpu-user").getDoubleValue());

    assertNotNull(attrs.get("recent-cpu-system"));
    assertFalse(attrs.get("recent-cpu-system").hasMultipleValues());
    assertNotNull(attrs.get("recent-cpu-system").getDoubleValue());

    assertNotNull(attrs.get("recent-cpu-iowait"));
    assertFalse(attrs.get("recent-cpu-iowait").hasMultipleValues());
    assertNotNull(attrs.get("recent-cpu-iowait").getDoubleValue());

    assertNotNull(attrs.get("recent-cpu-used"));
    assertFalse(attrs.get("recent-cpu-used").hasMultipleValues());
    assertNotNull(attrs.get("recent-cpu-used").getDoubleValue());

    assertNotNull(attrs.get("recent-cpu-idle"));
    assertFalse(attrs.get("recent-cpu-idle").hasMultipleValues());
    assertNotNull(attrs.get("recent-cpu-idle").getDoubleValue());

    assertNotNull(attrs.get("total-memory-gb"));
    assertFalse(attrs.get("total-memory-gb").hasMultipleValues());
    assertNotNull(attrs.get("total-memory-gb").getDoubleValue());

    assertNotNull(attrs.get("recent-memory-free-gb"));
    assertFalse(attrs.get("recent-memory-free-gb").hasMultipleValues());
    assertNotNull(attrs.get("recent-memory-free-gb").getDoubleValue());

    assertNotNull(attrs.get("recent-memory-pct-free"));
    assertFalse(attrs.get("recent-memory-pct-free").hasMultipleValues());
    assertNotNull(attrs.get("recent-memory-pct-free").getDoubleValue());
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
         "dn: cn=Host System Recent CPU and Memory,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-host-system-cpu-memory-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Host System Recent CPU and Memory");

    final HostSystemRecentCPUAndMemoryMonitorEntry me =
         new HostSystemRecentCPUAndMemoryMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
         "ds-host-system-cpu-memory-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         HostSystemRecentCPUAndMemoryMonitorEntry.class.getName());

    assertNull(me.getUpdateTime());

    assertNull(me.getRecentCPUTotalBusyPercent());

    assertNull(me.getRecentCPUUserPercent());

    assertNull(me.getRecentCPUSystemPercent());

    assertNull(me.getRecentCPUIOWaitPercent());

    assertNull(me.getRecentCPUIdlePercent());

    assertNull(me.getTotalSystemMemoryGB());

    assertNull(me.getRecentSystemMemoryPercentFree());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());


    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(attrs);
    assertTrue(attrs.isEmpty());
  }
}
