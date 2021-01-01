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
 * This class provides test coverage for the FIFOEntryCacheMonitorEntry class.
 */
public class FIFOEntryCacheMonitorEntryTestCase
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
         "dn: cn=FIFO Cache monitor,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-fifo-entry-cache-monitor-entry",
         "objectClass: extensibleObject",
         "cn: FIFO Cache monitor",
         "cacheName: FIFO Cache",
         "entryCacheHits: 1",
         "entryCacheTries: 2",
         "entryCacheHitRatio: 3",
         "maxEntryCacheSize: 4",
         "currentEntryCacheCount: 5",
         "maxEntryCacheCount: 6",
         "entriesAddedOrUpdated: 7",
         "evictionsDueToMaxMemory: 8",
         "evictionsDueToMaxEntries: 9",
         "entriesNotAddedAlreadyPresent: 10",
         "entriesNotAddedDueToMaxMemory: 11",
         "entriesNotAddedDueToFilter: 12",
         "entriesNotAddedDueToEntrySmallness: 13",
         "lowMemoryOccurrences: 14",
         "percentFullMaxEntries: 15",
         "jvmMemoryMaxPercentThreshold: 16",
         "jvmMemoryCurrentPercentFull: 17",
         "jvmMemoryBelowMaxMemoryPercent: 18",
         "isFull: true",
         "capacityDetails: This is the capacity details string");

    final FIFOEntryCacheMonitorEntry me = new FIFOEntryCacheMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-fifo-entry-cache-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 FIFOEntryCacheMonitorEntry.class.getName());

    assertNotNull(me.getCacheName());
    assertEquals(me.getCacheName(), "FIFO Cache");

    assertNotNull(me.getEntryCacheHits());
    assertEquals(me.getEntryCacheHits(), Long.valueOf(1L));

    assertNotNull(me.getEntryCacheTries());
    assertEquals(me.getEntryCacheTries(), Long.valueOf(2L));

    assertNotNull(me.getEntryCacheHitRatio());
    assertEquals(me.getEntryCacheHitRatio(), Long.valueOf(3L));

    assertNotNull(me.getMaxEntryCacheSizeBytes());
    assertEquals(me.getMaxEntryCacheSizeBytes(), Long.valueOf(4L));

    assertNotNull(me.getCurrentEntryCacheCount());
    assertEquals(me.getCurrentEntryCacheCount(), Long.valueOf(5L));

    assertNotNull(me.getMaxEntryCacheCount());
    assertEquals(me.getMaxEntryCacheCount(), Long.valueOf(6L));

    assertNotNull(me.getEntriesAddedOrUpdated());
    assertEquals(me.getEntriesAddedOrUpdated(), Long.valueOf(7L));

    assertNotNull(me.getEvictionsDueToMaxMemory());
    assertEquals(me.getEvictionsDueToMaxMemory(), Long.valueOf(8L));

    assertNotNull(me.getEvictionsDueToMaxEntries());
    assertEquals(me.getEvictionsDueToMaxEntries(), Long.valueOf(9L));

    assertNotNull(me.getEntriesNotAddedAlreadyPresent());
    assertEquals(me.getEntriesNotAddedAlreadyPresent(), Long.valueOf(10L));

    assertNotNull(me.getEntriesNotAddedDueToMaxMemory());
    assertEquals(me.getEntriesNotAddedDueToMaxMemory(), Long.valueOf(11L));

    assertNotNull(me.getEntriesNotAddedDueToFilter());
    assertEquals(me.getEntriesNotAddedDueToFilter(), Long.valueOf(12L));

    assertNotNull(me.getEntriesNotAddedDueToEntrySmallness());
    assertEquals(me.getEntriesNotAddedDueToEntrySmallness(), Long.valueOf(13L));

    assertNotNull(me.getLowMemoryOccurrences());
    assertEquals(me.getLowMemoryOccurrences(), Long.valueOf(14L));

    assertNotNull(me.getPercentFullMaxEntries());
    assertEquals(me.getPercentFullMaxEntries(), Long.valueOf(15L));

    assertNotNull(me.getJVMMemoryMaxPercentThreshold());
    assertEquals(me.getJVMMemoryMaxPercentThreshold(), Long.valueOf(16L));

    assertNotNull(me.getJVMMemoryCurrentPercentFull());
    assertEquals(me.getJVMMemoryCurrentPercentFull(), Long.valueOf(17L));

    assertNotNull(me.getJVMMemoryBelowMaxMemoryPercent());
    assertEquals(me.getJVMMemoryBelowMaxMemoryPercent(), Long.valueOf(18L));

    assertNotNull(me.isFull());
    assertTrue(me.isFull());

    assertNotNull(me.getCapacityDetails());
    assertEquals(me.getCapacityDetails(),
         "This is the capacity details string");


    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());


    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(attrs);
    assertFalse(attrs.isEmpty());

    assertNotNull(attrs.get("cacheName".toLowerCase()));
    assertEquals(attrs.get("cacheName".toLowerCase()).getStringValue(),
         "FIFO Cache");

    assertNotNull(attrs.get("entryCacheHits".toLowerCase()));
    assertEquals(attrs.get("entryCacheHits".toLowerCase()).getLongValue(),
         Long.valueOf(1L));

    assertNotNull(attrs.get("entryCacheTries".toLowerCase()));
    assertEquals(attrs.get("entryCacheTries".toLowerCase()).getLongValue(),
         Long.valueOf(2L));

    assertNotNull(attrs.get("entryCacheHitRatio".toLowerCase()));
    assertEquals(attrs.get("entryCacheHitRatio".toLowerCase()).getLongValue(),
         Long.valueOf(3L));

    assertNotNull(attrs.get("maxEntryCacheSize".toLowerCase()));
    assertEquals(attrs.get("maxEntryCacheSize".toLowerCase()).getLongValue(),
         Long.valueOf(4L));

    assertNotNull(attrs.get("currentEntryCacheCount".toLowerCase()));
    assertEquals(
         attrs.get("currentEntryCacheCount".toLowerCase()).getLongValue(),
         Long.valueOf(5L));

    assertNotNull(attrs.get("maxEntryCacheCount".toLowerCase()));
    assertEquals(attrs.get("maxEntryCacheCount".toLowerCase()).getLongValue(),
         Long.valueOf(6L));

    assertNotNull(attrs.get("entriesAddedOrUpdated".toLowerCase()));
    assertEquals(
         attrs.get("entriesAddedOrUpdated".toLowerCase()).getLongValue(),
         Long.valueOf(7L));

    assertNotNull(attrs.get("evictionsDueToMaxMemory".toLowerCase()));
    assertEquals(
         attrs.get("evictionsDueToMaxMemory".toLowerCase()).getLongValue(),
         Long.valueOf(8L));

    assertNotNull(attrs.get("evictionsDueToMaxEntries".toLowerCase()));
    assertEquals(
         attrs.get("evictionsDueToMaxEntries".toLowerCase()).getLongValue(),
         Long.valueOf(9L));

    assertNotNull(attrs.get("entriesNotAddedAlreadyPresent".toLowerCase()));
    assertEquals(attrs.get(
         "entriesNotAddedAlreadyPresent".toLowerCase()).getLongValue(),
         Long.valueOf(10L));

    assertNotNull(attrs.get("entriesNotAddedDueToMaxMemory".toLowerCase()));
    assertEquals(attrs.get(
         "entriesNotAddedDueToMaxMemory".toLowerCase()).getLongValue(),
         Long.valueOf(11L));

    assertNotNull(attrs.get("entriesNotAddedDueToFilter".toLowerCase()));
    assertEquals(
         attrs.get("entriesNotAddedDueToFilter".toLowerCase()).getLongValue(),
         Long.valueOf(12L));

    assertNotNull(attrs.get(
         "entriesNotAddedDueToEntrySmallness".toLowerCase()));
    assertEquals(attrs.get(
         "entriesNotAddedDueToEntrySmallness".toLowerCase()).getLongValue(),
         Long.valueOf(13L));

    assertNotNull(attrs.get("lowMemoryOccurrences".toLowerCase()));
    assertEquals(attrs.get("lowMemoryOccurrences".toLowerCase()).getLongValue(),
         Long.valueOf(14L));

    assertNotNull(attrs.get("percentFullMaxEntries".toLowerCase()));
    assertEquals(
         attrs.get("percentFullMaxEntries".toLowerCase()).getLongValue(),
         Long.valueOf(15L));

    assertNotNull(attrs.get("jvmMemoryMaxPercentThreshold".toLowerCase()));
    assertEquals(
         attrs.get("jvmMemoryMaxPercentThreshold".toLowerCase()).getLongValue(),
         Long.valueOf(16L));

    assertNotNull(attrs.get("jvmMemoryCurrentPercentFull".toLowerCase()));
    assertEquals(
         attrs.get("jvmMemoryCurrentPercentFull".toLowerCase()).getLongValue(),
         Long.valueOf(17L));

    assertNotNull(attrs.get("jvmMemoryBelowMaxMemoryPercent".toLowerCase()));
    assertEquals(attrs.get(
         "jvmMemoryBelowMaxMemoryPercent".toLowerCase()).getLongValue(),
         Long.valueOf(18L));

    assertNotNull(attrs.get("isFull".toLowerCase()));
    assertEquals(attrs.get("isFull".toLowerCase()).getBooleanValue(),
         Boolean.TRUE);

    assertNotNull(attrs.get("capacityDetails".toLowerCase()));
    assertEquals(attrs.get("capacityDetails".toLowerCase()).getStringValue(),
         "This is the capacity details string");
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
         "dn: cn=FIFO Cache monitor,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-fifo-entry-cache-monitor-entry",
         "objectClass: extensibleObject",
         "cn: FIFO Cache monitor");

    final FIFOEntryCacheMonitorEntry me = new FIFOEntryCacheMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-fifo-entry-cache-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 FIFOEntryCacheMonitorEntry.class.getName());

    assertNull(me.getCacheName());

    assertNull(me.getEntryCacheHits());

    assertNull(me.getEntryCacheTries());

    assertNull(me.getEntryCacheHitRatio());

    assertNull(me.getMaxEntryCacheSizeBytes());

    assertNull(me.getCurrentEntryCacheCount());

    assertNull(me.getMaxEntryCacheCount());

    assertNull(me.getEntriesAddedOrUpdated());

    assertNull(me.getEvictionsDueToMaxMemory());

    assertNull(me.getEvictionsDueToMaxEntries());

    assertNull(me.getEntriesNotAddedAlreadyPresent());

    assertNull(me.getEntriesNotAddedDueToMaxMemory());

    assertNull(me.getEntriesNotAddedDueToFilter());

    assertNull(me.getEntriesNotAddedDueToEntrySmallness());

    assertNull(me.getLowMemoryOccurrences());

    assertNull(me.getPercentFullMaxEntries());

    assertNull(me.getJVMMemoryMaxPercentThreshold());

    assertNull(me.getJVMMemoryCurrentPercentFull());

    assertNull(me.getJVMMemoryBelowMaxMemoryPercent());

    assertNull(me.isFull());

    assertNull(me.getCapacityDetails());


    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());


    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(attrs);
    assertTrue(attrs.isEmpty());
  }
}
