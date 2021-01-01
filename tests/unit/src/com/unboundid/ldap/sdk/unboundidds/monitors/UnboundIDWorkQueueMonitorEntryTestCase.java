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



/**
 * This class provides test coverage for the UnboundIDWorkQueueMonitorEntry
 * class.
 */
public class UnboundIDWorkQueueMonitorEntryTestCase
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
         "dn: cn=Work Queue,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-unboundid-work-queue-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Work Queue",
         "current-queue-size: 1",
         "average-queue-size: 2",
         "max-queue-size: 3",
         "rejected-count: 5",
         "stolen-count: 19",
         "num-worker-threads: 6",
         "average-worker-thread-percent-busy: 7",
         "recent-worker-thread-percent-busy: 8",
         "max-worker-thread-percent-busy: 9",
         "num-busy-worker-threads: 10",
         "average-operation-queue-time-millis: 11",
         "recent-operation-queue-time-millis: 12",
         "recent-average-queue-size: 13",
         "current-worker-thread-percent-busy: 14",
         "current-administrative-session-queue-size: 15",
         "num-administrative-session-worker-threads: 16",
         "num-busy-administrative-session-worker-threads: 17",
         "max-administrative-session-queue-size: 18");

    UnboundIDWorkQueueMonitorEntry me =
         new UnboundIDWorkQueueMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-unboundid-work-queue-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 UnboundIDWorkQueueMonitorEntry.class.getName());

    assertNotNull(me.getAverageSize());
    assertEquals(me.getAverageSize().longValue(), 2L);

    assertNotNull(me.getCurrentSize());
    assertEquals(me.getCurrentSize().longValue(), 1L);

    assertNotNull(me.getMaxSize());
    assertEquals(me.getMaxSize().longValue(), 3L);

    assertNotNull(me.getRequestsRejectedDueToQueueFull());
    assertEquals(me.getRequestsRejectedDueToQueueFull().longValue(), 5L);

    assertNotNull(me.getRequestsStolen());
    assertEquals(me.getRequestsStolen().longValue(), 19L);

    assertNotNull(me.getNumWorkerThreads());
    assertEquals(me.getNumWorkerThreads().longValue(), 6L);

    assertNotNull(me.getNumBusyWorkerThreads());
    assertEquals(me.getNumBusyWorkerThreads().longValue(), 10L);

    assertNotNull(me.getAverageWorkerThreadPercentBusy());
    assertEquals(me.getAverageWorkerThreadPercentBusy().longValue(), 7L);

    assertNotNull(me.getRecentWorkerThreadPercentBusy());
    assertEquals(me.getRecentWorkerThreadPercentBusy().longValue(), 8L);

    assertNotNull(me.getMaxWorkerThreadPercentBusy());
    assertEquals(me.getMaxWorkerThreadPercentBusy().longValue(), 9L);

    assertNotNull(me.getAverageOperationQueueTimeMillis());
    assertEquals(me.getAverageOperationQueueTimeMillis().longValue(), 11L);

    assertNotNull(me.getRecentOperationQueueTimeMillis());
    assertEquals(me.getRecentOperationQueueTimeMillis().longValue(), 12L);

    assertNotNull(me.getRecentAverageSize());
    assertEquals(me.getRecentAverageSize().longValue(), 13L);

    assertNotNull(me.getCurrentWorkerThreadPercentBusy());
    assertEquals(me.getCurrentWorkerThreadPercentBusy().longValue(), 14L);

    assertNotNull(me.getCurrentAdministrativeSessionQueueSize());
    assertEquals(me.getCurrentAdministrativeSessionQueueSize().longValue(),
         15L);

    assertNotNull(me.getNumAdministrativeSessionWorkerThreads());
    assertEquals(me.getNumAdministrativeSessionWorkerThreads().longValue(),
         16L);

    assertNotNull(me.getNumBusyAdministrativeSessionWorkerThreads());
    assertEquals(me.getNumBusyAdministrativeSessionWorkerThreads().longValue(),
         17L);

    assertNotNull(me.getMaxAdministrativeSessionQueueSize());
    assertEquals(me.getMaxAdministrativeSessionQueueSize().longValue(),
         18L);

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("current-queue-size"));
    assertEquals(attrs.get("current-queue-size").getLongValue(),
                 Long.valueOf(1));

    assertNotNull(attrs.get("average-queue-size"));
    assertEquals(attrs.get("average-queue-size").getLongValue(),
                 Long.valueOf(2));

    assertNotNull(attrs.get("max-queue-size"));
    assertEquals(attrs.get("max-queue-size").getLongValue(), Long.valueOf(3));

    assertNotNull(attrs.get("rejected-count"));
    assertEquals(attrs.get("rejected-count").getLongValue(), Long.valueOf(5));

    assertNotNull(attrs.get("stolen-count"));
    assertEquals(attrs.get("stolen-count").getLongValue(), Long.valueOf(19));

    assertNotNull(attrs.get("num-worker-threads"));
    assertEquals(attrs.get("num-worker-threads").getLongValue(),
                 Long.valueOf(6));

    assertNotNull(attrs.get("num-busy-worker-threads"));
    assertEquals(attrs.get("num-busy-worker-threads").getLongValue(),
                 Long.valueOf(10));

    assertNotNull(attrs.get("average-worker-thread-percent-busy"));
    assertEquals(attrs.get("average-worker-thread-percent-busy").getLongValue(),
                 Long.valueOf(7));

    assertNotNull(attrs.get("recent-worker-thread-percent-busy"));
    assertEquals(attrs.get("recent-worker-thread-percent-busy").getLongValue(),
                 Long.valueOf(8));

    assertNotNull(attrs.get("max-worker-thread-percent-busy"));
    assertEquals(attrs.get("max-worker-thread-percent-busy").getLongValue(),
                 Long.valueOf(9));

    assertNotNull(attrs.get("average-operation-queue-time-millis"));
    assertEquals(attrs.get("average-operation-queue-time-millis").
                      getLongValue(),
                 Long.valueOf(11));

    assertNotNull(attrs.get("recent-operation-queue-time-millis"));
    assertEquals(attrs.get("recent-operation-queue-time-millis").getLongValue(),
                 Long.valueOf(12));

    assertNotNull(attrs.get("recent-average-queue-size"));
    assertEquals(attrs.get("recent-average-queue-size").getLongValue(),
                 Long.valueOf(13));

    assertNotNull(attrs.get("current-worker-thread-percent-busy"));
    assertEquals(attrs.get("current-worker-thread-percent-busy").getLongValue(),
                 Long.valueOf(14));

    assertNotNull(attrs.get("current-administrative-session-queue-size"));
    assertEquals(attrs.get(
         "current-administrative-session-queue-size").getLongValue(),
         Long.valueOf(15));

    assertNotNull(attrs.get("num-administrative-session-worker-threads"));
    assertEquals(attrs.get(
         "num-administrative-session-worker-threads").getLongValue(),
         Long.valueOf(16));

    assertNotNull(attrs.get("num-busy-administrative-session-worker-threads"));
    assertEquals(attrs.get(
         "num-busy-administrative-session-worker-threads").getLongValue(),
         Long.valueOf(17));

    assertNotNull(attrs.get("max-administrative-session-queue-size"));
    assertEquals(attrs.get(
         "max-administrative-session-queue-size").getLongValue(),
         Long.valueOf(18));
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
         "dn: cn=Work Queue,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-unboundid-work-queue-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Work Queue");

    UnboundIDWorkQueueMonitorEntry me =
         new UnboundIDWorkQueueMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-unboundid-work-queue-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 UnboundIDWorkQueueMonitorEntry.class.getName());

    assertNull(me.getAverageSize());

    assertNull(me.getCurrentSize());

    assertNull(me.getMaxSize());

    assertNull(me.getRequestsRejectedDueToQueueFull());

    assertNull(me.getRequestsStolen());

    assertNull(me.getNumWorkerThreads());

    assertNull(me.getNumBusyWorkerThreads());

    assertNull(me.getAverageWorkerThreadPercentBusy());

    assertNull(me.getRecentWorkerThreadPercentBusy());

    assertNull(me.getMaxWorkerThreadPercentBusy());

    assertNull(me.getAverageOperationQueueTimeMillis());

    assertNull(me.getRecentOperationQueueTimeMillis());

    assertNull(me.getRecentAverageSize());

    assertNull(me.getCurrentWorkerThreadPercentBusy());

    assertNull(me.getCurrentAdministrativeSessionQueueSize());

    assertNull(me.getNumAdministrativeSessionWorkerThreads());

    assertNull(me.getNumBusyAdministrativeSessionWorkerThreads());

    assertNull(me.getMaxAdministrativeSessionQueueSize());
  }
}
