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
 * This class provides test coverage for the TraditionalWorkQueueMonitorEntry
 * class.
 */
public class TraditionalWorkQueueMonitorEntryTestCase
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
         "objectClass: ds-traditional-work-queue-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Work Queue",
         "currentRequestBacklog: 1",
         "averageRequestBacklog: 2",
         "maxRequestBacklog: 3",
         "requestsSubmitted: 4",
         "requestsRejectedDueToQueueFull: 5");

    TraditionalWorkQueueMonitorEntry me =
         new TraditionalWorkQueueMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-traditional-work-queue-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 TraditionalWorkQueueMonitorEntry.class.getName());

    assertNotNull(me.getAverageBacklog());
    assertEquals(me.getAverageBacklog().longValue(), 2L);

    assertNotNull(me.getCurrentBacklog());
    assertEquals(me.getCurrentBacklog().longValue(), 1L);

    assertNotNull(me.getMaxBacklog());
    assertEquals(me.getMaxBacklog().longValue(), 3L);

    assertNotNull(me.getRequestsSubmitted());
    assertEquals(me.getRequestsSubmitted().longValue(), 4L);

    assertNotNull(me.getRequestsRejectedDueToQueueFull());
    assertEquals(me.getRequestsRejectedDueToQueueFull().longValue(), 5L);

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("currentrequestbacklog"));
    assertEquals(attrs.get("currentrequestbacklog").getLongValue(),
                 Long.valueOf(1));

    assertNotNull(attrs.get("averagerequestbacklog"));
    assertEquals(attrs.get("averagerequestbacklog").getLongValue(),
                 Long.valueOf(2));

    assertNotNull(attrs.get("maxrequestbacklog"));
    assertEquals(attrs.get("maxrequestbacklog").getLongValue(),
                 Long.valueOf(3));

    assertNotNull(attrs.get("requestssubmitted"));
    assertEquals(attrs.get("requestssubmitted").getLongValue(),
                 Long.valueOf(4));

    assertNotNull(attrs.get("requestsrejectedduetoqueuefull"));
    assertEquals(attrs.get("requestsrejectedduetoqueuefull").getLongValue(),
                 Long.valueOf(5));
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
         "objectClass: ds-traditional-work-queue-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Work Queue");

    TraditionalWorkQueueMonitorEntry me =
         new TraditionalWorkQueueMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-traditional-work-queue-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 TraditionalWorkQueueMonitorEntry.class.getName());

    assertNull(me.getAverageBacklog());

    assertNull(me.getCurrentBacklog());

    assertNull(me.getMaxBacklog());

    assertNull(me.getRequestsSubmitted());

    assertNull(me.getRequestsRejectedDueToQueueFull());
  }
}
