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
 * This class provides test coverage for the GroupCacheMonitorEntry class.
 */
public class GroupCacheMonitorEntryTestCase
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
         "dn: cn=Group Cache,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-group-cache-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Group Cache",
         "static-group-entries: 5",
         "static-group-members: 20",
         "static-group-unique-members: 15",
         "virtual-static-group-entries: 1",
         "dynamic-group-entries: 2",
         "current-cache-used-bytes: 12345",
         "current-cache-used-as-percentage-of-max-heap: 3",
         "current-cache-used-update-ms: 67.89");

    final GroupCacheMonitorEntry me = new GroupCacheMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-group-cache-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         GroupCacheMonitorEntry.class.getName());

    assertNotNull(me.getStaticGroupEntries());
    assertEquals(me.getStaticGroupEntries(), Long.valueOf(5L));

    assertNotNull(me.getTotalStaticGroupMembers());
    assertEquals(me.getTotalStaticGroupMembers(), Long.valueOf(20));

    assertNotNull(me.getUniqueStaticGroupMembers());
    assertEquals(me.getUniqueStaticGroupMembers(), Long.valueOf(15));

    assertNotNull(me.getDynamicGroupEntries());
    assertEquals(me.getDynamicGroupEntries(), Long.valueOf(2L));

    assertNotNull(me.getVirtualStaticGroupEntries());
    assertEquals(me.getVirtualStaticGroupEntries(), Long.valueOf(1L));

    assertNotNull(me.getCurrentCacheUsedBytes());
    assertEquals(me.getCurrentCacheUsedBytes(), Long.valueOf(12345L));

    assertNotNull(me.getCurrentCacheUsedAsPercentOfMaxHeap());
    assertEquals(me.getCurrentCacheUsedAsPercentOfMaxHeap(),
         Integer.valueOf(3));

    assertNotNull(me.getCurrentCacheUsedUpdateDurationMillis());
    assertEquals(me.getCurrentCacheUsedUpdateDurationMillis(),
         Double.valueOf("67.89"));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());


    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(attrs);
    assertFalse(attrs.isEmpty());

    assertNotNull(attrs.get("static-group-entries"));
    assertFalse(attrs.get("static-group-entries").hasMultipleValues());
    assertNotNull(attrs.get("static-group-entries").getLongValue());

    assertNotNull(attrs.get("static-group-members"));
    assertFalse(attrs.get("static-group-members").hasMultipleValues());
    assertNotNull(attrs.get("static-group-members").getLongValue());

    assertNotNull(attrs.get("static-group-unique-members"));
    assertFalse(attrs.get("static-group-unique-members").hasMultipleValues());
    assertNotNull(attrs.get("static-group-unique-members").getLongValue());

    assertNotNull(attrs.get("dynamic-group-entries"));
    assertFalse(attrs.get("dynamic-group-entries").hasMultipleValues());
    assertNotNull(attrs.get("dynamic-group-entries").getLongValue());

    assertNotNull(attrs.get("virtual-static-group-entries"));
    assertFalse(attrs.get("virtual-static-group-entries").hasMultipleValues());
    assertNotNull(attrs.get("virtual-static-group-entries").getLongValue());

    assertNotNull(attrs.get("current-cache-used-bytes"));
    assertFalse(attrs.get("current-cache-used-bytes").hasMultipleValues());
    assertNotNull(attrs.get("current-cache-used-bytes").getLongValue());

    assertNotNull(attrs.get("current-cache-used-as-percentage-of-max-heap"));
    assertFalse(attrs.get("current-cache-used-as-percentage-of-max-heap").
         hasMultipleValues());
    assertNotNull(attrs.get("current-cache-used-as-percentage-of-max-heap").
         getIntegerValue());

    assertNotNull(attrs.get("current-cache-used-update-ms"));
    assertFalse(attrs.get("current-cache-used-update-ms").hasMultipleValues());
    assertNotNull(attrs.get("current-cache-used-update-ms").getDoubleValue());
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
         "dn: cn=Group Cache,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-group-cache-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Group Cache");

    final GroupCacheMonitorEntry me = new GroupCacheMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-group-cache-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         GroupCacheMonitorEntry.class.getName());

    assertNull(me.getStaticGroupEntries());

    assertNull(me.getTotalStaticGroupMembers());

    assertNull(me.getUniqueStaticGroupMembers());

    assertNull(me.getDynamicGroupEntries());

    assertNull(me.getVirtualStaticGroupEntries());

    assertNull(me.getCurrentCacheUsedBytes());

    assertNull(me.getCurrentCacheUsedAsPercentOfMaxHeap());

    assertNull(me.getCurrentCacheUsedUpdateDurationMillis());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());


    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(attrs);
    assertTrue(attrs.isEmpty());
  }
}
