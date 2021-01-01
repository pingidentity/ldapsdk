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
 * This class provides test coverage for the MemoryUsageMonitorEntry class.
 */
public class MemoryUsageMonitorEntryTestCase
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
         "dn: cn=JVM Memory Usage,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-memory-usage-monitor-entry",
         "objectClass: extensibleObject",
         "cn: JVM Memory Usage",
         "ps-scavenge-total-collection-count: 1",
         "ps-scavenge-total-collection-duration: 2",
         "ps-scavenge-average-collection-duration: 3",
         "ps-scavenge-recent-collection-duration: 4",
         "ps-mark-sweep-total-collection-count: 5",
         "ps-mark-sweep-total-collection-duration: 6",
         "ps-mark-sweep-average-collection-duration: 7",
         "ps-mark-sweep-recent-collection-duration: 8",
         "code-cache-current-bytes-used: 9",
         "code-cache-bytes-used-after-last-collection: 10",
         "ps-eden-space-current-bytes-used: 11",
         "ps-eden-space-bytes-used-after-last-collection: 12",
         "ps-survivor-space-current-bytes-used: 13",
         "ps-survivor-space-bytes-used-after-last-collection: 14",
         "ps-old-gen-current-bytes-used: 15",
         "ps-old-gen-bytes-used-after-last-collection: 16",
         "ps-perm-gen-current-bytes-used: 17",
         "ps-perm-gen-bytes-used-after-last-collection: 18",
         "non-heap-memory-bytes-used: 19",
         "detected-pauses-over-1s: 20",
         "detected-pauses-over-2s: 21",
         "detected-pauses-over-5s: 22",
         "detected-pauses-over-10s: 23",
         "detected-pauses-over-20s: 24",
         "detected-pauses-over-50s: 25",
         "detected-pauses-over-100s: 26",
         "max-detected-pause-time-millis: 27",
         "total-bytes-used-by-memory-consumers: 28",
         "memory-consumers-total-as-percent-of-maximum-tenured-memory: 29",
         "memory-consumers-total-as-percent-of-committed-tenured-memory: 30",
         "maxReservableMemoryMB: 31",
         "currentReservedMemoryMB: 32",
         "usedReservedMemoryMB: 33",
         "freeReservedMemoryMB: 34",
         "reservedMemoryPercentFull: 35");

    MemoryUsageMonitorEntry me = new MemoryUsageMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-memory-usage-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 MemoryUsageMonitorEntry.class.getName());

    assertNotNull(me.getGarbageCollectorNames());
    assertEquals(me.getGarbageCollectorNames().size(), 2);
    assertTrue(me.getGarbageCollectorNames().contains("ps-scavenge"));
    assertTrue(me.getGarbageCollectorNames().contains("ps-mark-sweep"));

    assertNotNull(me.getMemoryPoolNames());
    assertEquals(me.getMemoryPoolNames().size(), 5);
    assertTrue(me.getMemoryPoolNames().contains("code-cache"));
    assertTrue(me.getMemoryPoolNames().contains("ps-eden-space"));
    assertTrue(me.getMemoryPoolNames().contains("ps-survivor-space"));
    assertTrue(me.getMemoryPoolNames().contains("ps-old-gen"));
    assertTrue(me.getMemoryPoolNames().contains("ps-perm-gen"));

    assertNotNull(me.getTotalCollectionCounts());
    assertEquals(me.getTotalCollectionCounts().size(), 2);

    assertNotNull(me.getTotalCollectionCount("ps-scavenge"));
    assertEquals(me.getTotalCollectionCount("ps-scavenge").longValue(), 1L);

    assertNotNull(me.getTotalCollectionCount("ps-mark-sweep"));
    assertEquals(me.getTotalCollectionCount("ps-mark-sweep").longValue(), 5L);

    assertNull(me.getTotalCollectionCount("invalid"));

    assertNotNull(me.getTotalCollectionDurations());
    assertEquals(me.getTotalCollectionDurations().size(), 2);

    assertNotNull(me.getTotalCollectionDuration("ps-scavenge"));
    assertEquals(me.getTotalCollectionDuration("ps-scavenge").longValue(), 2L);

    assertNotNull(me.getTotalCollectionDuration("ps-mark-sweep"));
    assertEquals(me.getTotalCollectionDuration("ps-mark-sweep").longValue(),
                 6L);

    assertNull(me.getTotalCollectionDuration("invalid"));

    assertNotNull(me.getAverageCollectionDurations());
    assertEquals(me.getAverageCollectionDurations().size(), 2);

    assertNotNull(me.getAverageCollectionDuration("ps-scavenge"));
    assertEquals(me.getAverageCollectionDuration("ps-scavenge").longValue(),
                 3L);

    assertNotNull(me.getAverageCollectionDuration("ps-mark-sweep"));
    assertEquals(me.getAverageCollectionDuration("ps-mark-sweep").longValue(),
                 7L);

    assertNull(me.getAverageCollectionDuration("invalid"));

    assertNotNull(me.getRecentCollectionDurations());
    assertEquals(me.getRecentCollectionDurations().size(), 2);

    assertNotNull(me.getRecentCollectionDuration("ps-scavenge"));
    assertEquals(me.getRecentCollectionDuration("ps-scavenge").longValue(),
                 4L);

    assertNotNull(me.getRecentCollectionDuration("ps-mark-sweep"));
    assertEquals(me.getRecentCollectionDuration("ps-mark-sweep").longValue(),
                 8L);

    assertNull(me.getRecentCollectionDuration("invalid"));

    assertNotNull(me.getCurrentBytesUsed());
    assertEquals(me.getCurrentBytesUsed().size(), 5);

    assertNotNull(me.getCurrentBytesUsed("code-cache"));
    assertEquals(me.getCurrentBytesUsed("code-cache").longValue(), 9L);

    assertNotNull(me.getCurrentBytesUsed("ps-eden-space"));
    assertEquals(me.getCurrentBytesUsed("ps-eden-space").longValue(), 11L);

    assertNotNull(me.getCurrentBytesUsed("ps-survivor-space"));
    assertEquals(me.getCurrentBytesUsed("ps-survivor-space").longValue(), 13L);

    assertNotNull(me.getCurrentBytesUsed("ps-old-gen"));
    assertEquals(me.getCurrentBytesUsed("ps-old-gen").longValue(), 15L);

    assertNotNull(me.getCurrentBytesUsed("ps-perm-gen"));
    assertEquals(me.getCurrentBytesUsed("ps-perm-gen").longValue(), 17L);

    assertNull(me.getCurrentBytesUsed("invalid"));

    assertNotNull(me.getBytesUsedAfterLastCollection());
    assertEquals(me.getBytesUsedAfterLastCollection().size(), 5);

    assertNotNull(me.getBytesUsedAfterLastCollection("code-cache"));
    assertEquals(me.getBytesUsedAfterLastCollection("code-cache").longValue(),
                 10L);

    assertNotNull(me.getBytesUsedAfterLastCollection("ps-eden-space"));
    assertEquals(
         me.getBytesUsedAfterLastCollection("ps-eden-space").longValue(), 12L);

    assertNotNull(me.getBytesUsedAfterLastCollection("ps-survivor-space"));
    assertEquals(
         me.getBytesUsedAfterLastCollection("ps-survivor-space").longValue(),
         14L);

    assertNotNull(me.getBytesUsedAfterLastCollection("ps-old-gen"));
    assertEquals(me.getBytesUsedAfterLastCollection("ps-old-gen").longValue(),
                 16L);

    assertNotNull(me.getBytesUsedAfterLastCollection("ps-perm-gen"));
    assertEquals(me.getBytesUsedAfterLastCollection("ps-perm-gen").longValue(),
                 18L);

    assertNull(me.getBytesUsedAfterLastCollection("invalid"));

    assertNotNull(me.getNonHeapMemoryBytesUsed());
    assertEquals(me.getNonHeapMemoryBytesUsed(), Long.valueOf(19L));

    assertNotNull(me.getDetectedPauseCounts());
    assertEquals(me.getDetectedPauseCounts().size(), 7);
    assertEquals(me.getDetectedPauseCounts().get(1000L), Long.valueOf(20));
    assertEquals(me.getDetectedPauseCounts().get(2000L), Long.valueOf(21));
    assertEquals(me.getDetectedPauseCounts().get(5000L), Long.valueOf(22));
    assertEquals(me.getDetectedPauseCounts().get(10000L), Long.valueOf(23));
    assertEquals(me.getDetectedPauseCounts().get(20000L), Long.valueOf(24));
    assertEquals(me.getDetectedPauseCounts().get(50000L), Long.valueOf(25));
    assertEquals(me.getDetectedPauseCounts().get(100000L), Long.valueOf(26));

    assertNotNull(me.getMaxDetectedPauseTimeMillis());
    assertEquals(me.getMaxDetectedPauseTimeMillis(), Long.valueOf(27L));

    assertNotNull(me.getTotalBytesUsedByMemoryConsumers());
    assertEquals(me.getTotalBytesUsedByMemoryConsumers(), Long.valueOf(28L));

    assertNotNull(
         me.getPercentageOfMaximumTenuredMemoryUsedByMemoryConsumers());
    assertEquals(me.getPercentageOfMaximumTenuredMemoryUsedByMemoryConsumers(),
                 Long.valueOf(29L));

    assertNotNull(
         me.getPercentageOfCommittedTenuredMemoryUsedByMemoryConsumers());
    assertEquals(
         me.getPercentageOfCommittedTenuredMemoryUsedByMemoryConsumers(),
         Long.valueOf(30L));

    assertNotNull(me.getMaxReservableMemoryMB());
    assertEquals(me.getMaxReservableMemoryMB(), Long.valueOf(31L));

    assertNotNull(me.getCurrentReservedMemoryMB());
    assertEquals(me.getCurrentReservedMemoryMB(), Long.valueOf(32L));

    assertNotNull(me.getUsedReservedMemoryMB());
    assertEquals(me.getUsedReservedMemoryMB(), Long.valueOf(33L));

    assertNotNull(me.getFreeReservedMemoryMB());
    assertEquals(me.getFreeReservedMemoryMB(), Long.valueOf(34L));

    assertNotNull(me.getReservedMemoryPercentFull());
    assertEquals(me.getReservedMemoryPercentFull(), Long.valueOf(35L));


    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("gcnames"));
    assertTrue(attrs.get("gcnames").hasMultipleValues());
    assertEquals(attrs.get("gcnames").getStringValues().size(), 2);

    assertNotNull(attrs.get("totalcollectioncount-ps-scavenge"));
    assertEquals(attrs.get("totalcollectioncount-ps-scavenge").getLongValue(),
                 Long.valueOf(1));

    assertNotNull(attrs.get("totalcollectionduration-ps-scavenge"));
    assertEquals(
         attrs.get("totalcollectionduration-ps-scavenge").getLongValue(),
         Long.valueOf(2));

    assertNotNull(attrs.get("averagecollectionduration-ps-scavenge"));
    assertEquals(
         attrs.get("averagecollectionduration-ps-scavenge").getLongValue(),
         Long.valueOf(3));

    assertNotNull(attrs.get("recentcollectionduration-ps-scavenge"));
    assertEquals(
         attrs.get("recentcollectionduration-ps-scavenge").getLongValue(),
         Long.valueOf(4));

    assertNotNull(attrs.get("totalcollectioncount-ps-mark-sweep"));
    assertEquals(attrs.get("totalcollectioncount-ps-mark-sweep").getLongValue(),
                 Long.valueOf(5));

    assertNotNull(attrs.get("totalcollectionduration-ps-mark-sweep"));
    assertEquals(
         attrs.get("totalcollectionduration-ps-mark-sweep").getLongValue(),
         Long.valueOf(6));

    assertNotNull(attrs.get("averagecollectionduration-ps-mark-sweep"));
    assertEquals(
         attrs.get("averagecollectionduration-ps-mark-sweep").getLongValue(),
         Long.valueOf(7));

    assertNotNull(attrs.get("recentcollectionduration-ps-mark-sweep"));
    assertEquals(
         attrs.get("recentcollectionduration-ps-mark-sweep").getLongValue(),
         Long.valueOf(8));

    assertNotNull(attrs.get("memorypools"));
    assertTrue(attrs.get("memorypools").hasMultipleValues());
    assertEquals(attrs.get("memorypools").getStringValues().size(), 5);

    assertNotNull(attrs.get("currentbytesused-code-cache"));
    assertEquals(attrs.get("currentbytesused-code-cache").getLongValue(),
                 Long.valueOf(9));

    assertNotNull(attrs.get("bytesusedafterlastcollection-code-cache"));
    assertEquals(
         attrs.get("bytesusedafterlastcollection-code-cache").getLongValue(),
         Long.valueOf(10));

    assertNotNull(attrs.get("currentbytesused-ps-eden-space"));
    assertEquals(attrs.get("currentbytesused-ps-eden-space").getLongValue(),
                 Long.valueOf(11));

    assertNotNull(attrs.get("bytesusedafterlastcollection-ps-eden-space"));
    assertEquals(
         attrs.get("bytesusedafterlastcollection-ps-eden-space").getLongValue(),
         Long.valueOf(12));

    assertNotNull(attrs.get("currentbytesused-ps-survivor-space"));
    assertEquals(attrs.get("currentbytesused-ps-survivor-space").getLongValue(),
                 Long.valueOf(13));

    assertNotNull(attrs.get("bytesusedafterlastcollection-ps-survivor-space"));
    assertEquals(attrs.get("bytesusedafterlastcollection-ps-survivor-space").
                      getLongValue(),
                 Long.valueOf(14));

    assertNotNull(attrs.get("currentbytesused-ps-old-gen"));
    assertEquals(attrs.get("currentbytesused-ps-old-gen").getLongValue(),
                 Long.valueOf(15));

    assertNotNull(attrs.get("bytesusedafterlastcollection-ps-old-gen"));
    assertEquals(
         attrs.get("bytesusedafterlastcollection-ps-old-gen").getLongValue(),
         Long.valueOf(16));

    assertNotNull(attrs.get("currentbytesused-ps-perm-gen"));
    assertEquals(attrs.get("currentbytesused-ps-perm-gen").getLongValue(),
                 Long.valueOf(17));

    assertNotNull(attrs.get("bytesusedafterlastcollection-ps-perm-gen"));
    assertEquals(
         attrs.get("bytesusedafterlastcollection-ps-perm-gen").getLongValue(),
         Long.valueOf(18));

    assertNotNull(attrs.get("non-heap-memory-bytes-used"));
    assertEquals(attrs.get("non-heap-memory-bytes-used").getLongValue(),
                 Long.valueOf(19L));

    assertNotNull(attrs.get("detected-pause-counts"));
    assertEquals(attrs.get("detected-pause-counts").getStringValues().size(),
                 7);

    assertNotNull(attrs.get("max-detected-pause-time-millis"));
    assertEquals(attrs.get("max-detected-pause-time-millis").getLongValue(),
                 Long.valueOf(27L));

    assertNotNull(attrs.get("total-bytes-used-by-memory-consumers"));
    assertEquals(
         attrs.get("total-bytes-used-by-memory-consumers").getLongValue(),
         Long.valueOf(28L));

    assertNotNull(attrs.get(
         "memory-consumers-total-as-percent-of-maximum-tenured-memory"));
    assertEquals(attrs.get(
         "memory-consumers-total-as-percent-of-maximum-tenured-memory").
              getLongValue(),
         Long.valueOf(29L));

    assertNotNull(attrs.get(
         "memory-consumers-total-as-percent-of-committed-tenured-memory"));
    assertEquals(attrs.get(
         "memory-consumers-total-as-percent-of-committed-tenured-memory").
              getLongValue(),
         Long.valueOf(30L));

    assertNotNull(attrs.get("maxReservableMemoryMB".toLowerCase()));
    assertEquals(
         attrs.get("maxReservableMemoryMB".toLowerCase()).getLongValue(),
         Long.valueOf(31L));

    assertNotNull(attrs.get("currentReservedMemoryMB".toLowerCase()));
    assertEquals(
         attrs.get("currentReservedMemoryMB".toLowerCase()).getLongValue(),
         Long.valueOf(32L));

    assertNotNull(attrs.get("usedReservedMemoryMB".toLowerCase()));
    assertEquals(
         attrs.get("usedReservedMemoryMB".toLowerCase()).getLongValue(),
         Long.valueOf(33L));

    assertNotNull(attrs.get("freeReservedMemoryMB".toLowerCase()));
    assertEquals(
         attrs.get("freeReservedMemoryMB".toLowerCase()).getLongValue(),
         Long.valueOf(34L));

    assertNotNull(attrs.get("reservedMemoryPercentFull".toLowerCase()));
    assertEquals(
         attrs.get("reservedMemoryPercentFull".toLowerCase()).getLongValue(),
         Long.valueOf(35L));
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
         "dn: cn=JVM Memory Usage,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-memory-usage-monitor-entry",
         "objectClass: extensibleObject",
         "cn: JVM Memory Usage");

    MemoryUsageMonitorEntry me = new MemoryUsageMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-memory-usage-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 MemoryUsageMonitorEntry.class.getName());

    assertNotNull(me.getGarbageCollectorNames());
    assertEquals(me.getGarbageCollectorNames().size(), 0);

    assertNotNull(me.getMemoryPoolNames());
    assertEquals(me.getMemoryPoolNames().size(), 0);

    assertNotNull(me.getTotalCollectionCounts());
    assertEquals(me.getTotalCollectionCounts().size(), 0);

    assertNotNull(me.getTotalCollectionDurations());
    assertEquals(me.getTotalCollectionDurations().size(), 0);

    assertNotNull(me.getAverageCollectionDurations());
    assertEquals(me.getAverageCollectionDurations().size(), 0);

    assertNotNull(me.getRecentCollectionDurations());
    assertEquals(me.getRecentCollectionDurations().size(), 0);

    assertNotNull(me.getCurrentBytesUsed());
    assertEquals(me.getCurrentBytesUsed().size(), 0);

    assertNotNull(me.getBytesUsedAfterLastCollection());
    assertEquals(me.getBytesUsedAfterLastCollection().size(), 0);

    assertNull(me.getNonHeapMemoryBytesUsed());

    assertNotNull(me.getDetectedPauseCounts());
    assertEquals(me.getDetectedPauseCounts().size(), 0);

    assertNull(me.getMaxDetectedPauseTimeMillis());

    assertNull(me.getTotalBytesUsedByMemoryConsumers());

    assertNull(me.getPercentageOfMaximumTenuredMemoryUsedByMemoryConsumers());

    assertNull(me.getPercentageOfCommittedTenuredMemoryUsedByMemoryConsumers());

    assertNull(me.getMaxReservableMemoryMB());

    assertNull(me.getCurrentReservedMemoryMB());

    assertNull(me.getUsedReservedMemoryMB());

    assertNull(me.getFreeReservedMemoryMB());

    assertNull(me.getReservedMemoryPercentFull());
  }
}
