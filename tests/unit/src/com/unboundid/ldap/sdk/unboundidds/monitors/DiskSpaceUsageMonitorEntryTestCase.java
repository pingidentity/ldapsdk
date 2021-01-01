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
 * This class provides test coverage for the DiskSpaceUsageMonitorEntry class.
 */
public class DiskSpaceUsageMonitorEntryTestCase
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
         "dn: cn=Disk Space Usage,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-disk-space-usage-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Disk Space Usage",
         "current-disk-space-state: normal",
         "disk-space-consumer-name-1: First",
         "disk-space-consumer-path-1: first/path",
         "disk-space-consumer-total-bytes-1: 12345",
         "disk-space-consumer-usable-bytes-1: 6789",
         "disk-space-consumer-usable-percent-1: 55",
         "disk-space-consumer-name-2: Second",
         "disk-space-consumer-path-2: second/path",
         "disk-space-consumer-total-bytes-2: 9876",
         "disk-space-consumer-usable-bytes-2: 4321",
         "disk-space-consumer-usable-percent-2: 44");

    DiskSpaceUsageMonitorEntry me = new DiskSpaceUsageMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-disk-space-usage-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 DiskSpaceUsageMonitorEntry.class.getName());

    assertNotNull(me.getCurrentState());
    assertEquals(me.getCurrentState(), "normal");

    assertNotNull(me.getDiskSpaceInfo());
    assertEquals(me.getDiskSpaceInfo().size(), 2);

    DiskSpaceInfo i = me.getDiskSpaceInfo().get(0);
    assertNotNull(i);
    assertNotNull(i.toString());

    assertNotNull(i.getConsumerName());
    assertEquals(i.getConsumerName(), "First");

    assertNotNull(i.getPath());
    assertEquals(i.getPath(), "first/path");

    assertNotNull(i.getTotalBytes());
    assertEquals(i.getTotalBytes(), Long.valueOf(12345L));

    assertNotNull(i.getUsableBytes());
    assertEquals(i.getUsableBytes(), Long.valueOf(6789L));

    assertNotNull(i.getUsablePercent());
    assertEquals(i.getUsablePercent(), Long.valueOf(55L));

    i = me.getDiskSpaceInfo().get(1);
    assertNotNull(i);
    assertNotNull(i.toString());

    assertNotNull(i.getConsumerName());
    assertEquals(i.getConsumerName(), "Second");

    assertNotNull(i.getPath());
    assertEquals(i.getPath(), "second/path");

    assertNotNull(i.getTotalBytes());
    assertEquals(i.getTotalBytes(), Long.valueOf(9876L));

    assertNotNull(i.getUsableBytes());
    assertEquals(i.getUsableBytes(), Long.valueOf(4321L));

    assertNotNull(i.getUsablePercent());
    assertEquals(i.getUsablePercent(), Long.valueOf(44L));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("current-disk-space-state"));
    assertEquals(attrs.get("current-disk-space-state").getStringValue(),
                 "normal");

    assertNotNull(attrs.get("disk-space-consumer-name-1"));
    assertNotNull(attrs.get("disk-space-consumer-name-2"));
    assertNull(attrs.get("disk-space-consumer-name-3"));

    assertNotNull(attrs.get("disk-space-consumer-path-1"));
    assertNotNull(attrs.get("disk-space-consumer-path-2"));
    assertNull(attrs.get("disk-space-consumer-path-3"));

    assertNotNull(attrs.get("disk-space-consumer-total-bytes-1"));
    assertNotNull(attrs.get("disk-space-consumer-total-bytes-2"));
    assertNull(attrs.get("disk-space-consumer-total-bytes-3"));

    assertNotNull(attrs.get("disk-space-consumer-usable-bytes-1"));
    assertNotNull(attrs.get("disk-space-consumer-usable-bytes-2"));
    assertNull(attrs.get("disk-space-consumer-usable-bytes-3"));

    assertNotNull(attrs.get("disk-space-consumer-usable-percent-1"));
    assertNotNull(attrs.get("disk-space-consumer-usable-percent-2"));
    assertNull(attrs.get("disk-space-consumer-usable-percent-3"));
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
         "dn: cn=Disk Space Usage,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-disk-space-usage-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Disk Space Usage");

    DiskSpaceUsageMonitorEntry me = new DiskSpaceUsageMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-disk-space-usage-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 DiskSpaceUsageMonitorEntry.class.getName());

    assertNull(me.getCurrentState());

    assertNotNull(me.getDiskSpaceInfo());
    assertEquals(me.getDiskSpaceInfo().size(), 0);
  }
}
