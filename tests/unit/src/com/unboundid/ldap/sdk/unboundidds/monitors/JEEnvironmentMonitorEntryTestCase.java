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
 * This class provides test coverage for the JEEnvironmentMonitorEntry class.
 */
public class JEEnvironmentMonitorEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor with a valid entry with all
   * values present, using the new format for checkpoint information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testConstructorAllValues()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=userRoot Database Environment,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-je-environment-monitor-entry",
         "objectClass: extensibleObject",
         "cn: userRoot Database Environment",
         "je-version: 3.3.69",
         "backend-id: userRoot",
         "current-db-cache-size: 1234",
         "max-db-cache-size: 5678",
         "db-cache-percent-full: 22",
         "db-directory: db/userRoot",
         "db-on-disk-size: 12345",
         "cleaner-backlog: 1",
         "random-read-count: 2",
         "random-write-count: 3",
         "sequential-read-count: 4",
         "sequential-write-count: 5",
         "nodes-evicted: 6",
         "active-transaction-count: 7",
         "num-checkpoints: 11",
         "checkpoint-in-progress: false",
         "total-checkpoint-duration-millis: 12",
         "average-checkpoint-duration-millis: 13",
         "last-checkpoint-duration-millis: 14",
         "millis-since-last-checkpoint: 15",
         "last-checkpoint-start-time: 20080101010101.000Z",
         "last-checkpoint-stop-time: 20080101010101.001Z",
         "last-checkpoint-time: 20080101010101.002Z",
         "read-locks-held: 8",
         "write-locks-held: 9",
         "transactions-waiting-on-locks: 10",
         "je-env-stat-CacheTotalBytes: 1234",
         "je-env-stat-CleanerBacklog: 1",
         "je-lock-stat-NReadLocks: 8",
         "je-lock-stat-NWriteLocks: 9",
         "je-lock-stat-NWaiters: 10",
         "je-txn-stat-NActive: 7");

    JEEnvironmentMonitorEntry me = new JEEnvironmentMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-je-environment-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 JEEnvironmentMonitorEntry.class.getName());

    assertNotNull(me.getJEVersion());
    assertEquals(me.getJEVersion(), "3.3.69");

    assertNotNull(me.getBackendID());
    assertEquals(me.getBackendID(), "userRoot");

    assertNotNull(me.getCurrentDBCacheSize());
    assertEquals(me.getCurrentDBCacheSize(), Long.valueOf(1234L));

    assertNotNull(me.getMaxDBCacheSize());
    assertEquals(me.getMaxDBCacheSize(), Long.valueOf(5678L));

    assertNotNull(me.getDBCachePercentFull());
    assertEquals(me.getDBCachePercentFull(), Long.valueOf(22L));

    assertNotNull(me.getDBDirectory());
    assertEquals(me.getDBDirectory(), "db/userRoot");

    assertNotNull(me.getDBOnDiskSize());
    assertEquals(me.getDBOnDiskSize(), Long.valueOf(12345L));

    assertNotNull(me.getCleanerBacklog());
    assertEquals(me.getCleanerBacklog(), Long.valueOf(1L));

    assertNotNull(me.getRandomReads());
    assertEquals(me.getRandomReads(), Long.valueOf(2L));

    assertNotNull(me.getRandomWrites());
    assertEquals(me.getRandomWrites(), Long.valueOf(3L));

    assertNotNull(me.getSequentialReads());
    assertEquals(me.getSequentialReads(), Long.valueOf(4L));

    assertNotNull(me.getSequentialWrites());
    assertEquals(me.getSequentialWrites(), Long.valueOf(5L));

    assertNotNull(me.getNodesEvicted());
    assertEquals(me.getNodesEvicted(), Long.valueOf(6L));

    assertNotNull(me.getActiveTransactionCount());
    assertEquals(me.getActiveTransactionCount(), Long.valueOf(7L));

    assertNotNull(me.getNumCheckpoints());
    assertEquals(me.getNumCheckpoints(), Long.valueOf(11L));

    assertNotNull(me.checkpointInProgress());
    assertEquals(me.checkpointInProgress(), Boolean.FALSE);

    assertNotNull(me.getTotalCheckpointDurationMillis());
    assertEquals(me.getTotalCheckpointDurationMillis(), Long.valueOf(12L));

    assertNotNull(me.getAverageCheckpointDurationMillis());
    assertEquals(me.getAverageCheckpointDurationMillis(), Long.valueOf(13L));

    assertNotNull(me.getLastCheckpointDurationMillis());
    assertEquals(me.getLastCheckpointDurationMillis(), Long.valueOf(14L));

    assertNotNull(me.getLastCheckpointStartTime());

    assertNotNull(me.getLastCheckpointStopTime());

    assertNotNull(me.getLastCheckpointTime());

    assertNotNull(me.getMillisSinceLastCheckpoint());
    assertEquals(me.getMillisSinceLastCheckpoint(), Long.valueOf(15L));

    assertNotNull(me.getReadLocksHeld());
    assertEquals(me.getReadLocksHeld(), Long.valueOf(8L));

    assertNotNull(me.getWriteLocksHeld());
    assertEquals(me.getWriteLocksHeld(), Long.valueOf(9L));

    assertNotNull(me.getTransactionsWaitingOnLocks());
    assertEquals(me.getTransactionsWaitingOnLocks(), Long.valueOf(10L));

    assertNotNull(me.getEnvironmentStats());
    assertEquals(me.getEnvironmentStats().size(), 2);

    assertNotNull(me.getEnvironmentStat("CacheTotalBytes"));
    assertNotNull(me.getEnvironmentStat("cachetotalbytes"));
    assertNull(me.getEnvironmentStat("undefined"));

    assertNotNull(me.getLockStats());
    assertEquals(me.getLockStats().size(), 3);

    assertNotNull(me.getLockStat("NReadLocks"));
    assertNotNull(me.getLockStat("nreadlocks"));
    assertNull(me.getLockStat("undefined"));

    assertNotNull(me.getTransactionStats());
    assertEquals(me.getTransactionStats().size(), 1);

    assertNotNull(me.getTransactionStat("NActive"));
    assertNotNull(me.getTransactionStat("nactive"));
    assertNull(me.getLockStat("undefined"));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("backend-id"));
    assertEquals(attrs.get("backend-id").getStringValue(), "userRoot");

    assertNotNull(attrs.get("je-version"));
    assertEquals(attrs.get("je-version").getStringValue(), "3.3.69");

    assertNotNull(attrs.get("current-db-cache-size"));
    assertEquals(attrs.get("current-db-cache-size").getLongValue(),
                 Long.valueOf(1234L));

    assertNotNull(attrs.get("max-db-cache-size"));
    assertEquals(attrs.get("max-db-cache-size").getLongValue(),
                 Long.valueOf(5678L));

    assertNotNull(attrs.get("db-cache-percent-full"));
    assertEquals(attrs.get("db-cache-percent-full").getLongValue(),
                 Long.valueOf(22L));

    assertNotNull(attrs.get("db-directory"));
    assertEquals(attrs.get("db-directory").getStringValue(), "db/userRoot");

    assertNotNull(attrs.get("db-on-disk-size"));
    assertEquals(attrs.get("db-on-disk-size").getLongValue(),
                 Long.valueOf(12345L));

    assertNotNull(attrs.get("cleaner-backlog"));
    assertEquals(attrs.get("cleaner-backlog").getLongValue(), Long.valueOf(1L));

    assertNotNull(attrs.get("random-read-count"));
    assertEquals(attrs.get("random-read-count").getLongValue(),
                 Long.valueOf(2L));

    assertNotNull(attrs.get("random-write-count"));
    assertEquals(attrs.get("random-write-count").getLongValue(),
                 Long.valueOf(3L));

    assertNotNull(attrs.get("sequential-read-count"));
    assertEquals(attrs.get("sequential-read-count").getLongValue(),
                 Long.valueOf(4L));

    assertNotNull(attrs.get("sequential-write-count"));
    assertEquals(attrs.get("sequential-write-count").getLongValue(),
                 Long.valueOf(5L));

    assertNotNull(attrs.get("nodes-evicted"));
    assertEquals(attrs.get("nodes-evicted").getLongValue(),
                 Long.valueOf(6L));

    assertNotNull(attrs.get("active-transaction-count"));
    assertEquals(attrs.get("active-transaction-count").getLongValue(),
                 Long.valueOf(7L));

    assertNotNull(attrs.get("num-checkpoints"));
    assertEquals(attrs.get("num-checkpoints").getLongValue(),
                 Long.valueOf(11L));

    assertNotNull(attrs.get("checkpoint-in-progress"));
    assertEquals(attrs.get("checkpoint-in-progress").getBooleanValue(),
                 Boolean.FALSE);

    assertNotNull(attrs.get("total-checkpoint-duration-millis"));
    assertEquals(attrs.get("total-checkpoint-duration-millis").getLongValue(),
                 Long.valueOf(12L));

    assertNotNull(attrs.get("average-checkpoint-duration-millis"));
    assertEquals(attrs.get("average-checkpoint-duration-millis").getLongValue(),
                 Long.valueOf(13L));

    assertNotNull(attrs.get("last-checkpoint-duration-millis"));
    assertEquals(attrs.get("last-checkpoint-duration-millis").getLongValue(),
                 Long.valueOf(14L));

    assertNotNull(attrs.get("millis-since-last-checkpoint"));
    assertEquals(attrs.get("millis-since-last-checkpoint").getLongValue(),
                 Long.valueOf(15L));

    assertNotNull(attrs.get("last-checkpoint-start-time"));

    assertNotNull(attrs.get("last-checkpoint-stop-time"));

    assertNull(attrs.get("last-checkpoint-time"));

    assertNotNull(attrs.get("read-locks-held"));
    assertEquals(attrs.get("read-locks-held").getLongValue(),
                 Long.valueOf(8L));

    assertNotNull(attrs.get("write-locks-held"));
    assertEquals(attrs.get("write-locks-held").getLongValue(),
                 Long.valueOf(9L));

    assertNotNull(attrs.get("transactions-waiting-on-locks"));
    assertEquals(attrs.get("transactions-waiting-on-locks").getLongValue(),
                 Long.valueOf(10L));

    assertNotNull(attrs.get("je-env-stats"));
    assertEquals(attrs.get("je-env-stats").getStringValues().size(), 2);

    assertNotNull(attrs.get("je-lock-stats"));
    assertEquals(attrs.get("je-lock-stats").getStringValues().size(), 3);

    assertNotNull(attrs.get("je-txn-stats"));
    assertEquals(attrs.get("je-txn-stats").getStringValues().size(), 1);
  }



  /**
   * Provides test coverage for the constructor with a valid entry with no
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testConstructorNoValues()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=userRoot Database Environment,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-je-environment-monitor-entry",
         "objectClass: extensibleObject",
         "cn: userRoot Database Environment");

    JEEnvironmentMonitorEntry me = new JEEnvironmentMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-je-environment-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 JEEnvironmentMonitorEntry.class.getName());

    assertNull(me.getJEVersion());

    assertNull(me.getBackendID());

    assertNull(me.getCurrentDBCacheSize());

    assertNull(me.getMaxDBCacheSize());

    assertNull(me.getDBCachePercentFull());

    assertNull(me.getDBDirectory());

    assertNull(me.getDBOnDiskSize());

    assertNull(me.getCleanerBacklog());

    assertNull(me.getRandomReads());

    assertNull(me.getRandomWrites());

    assertNull(me.getSequentialReads());

    assertNull(me.getSequentialWrites());

    assertNull(me.getNodesEvicted());

    assertNull(me.getActiveTransactionCount());

    assertNull(me.getNumCheckpoints());

    assertNull(me.checkpointInProgress());

    assertNull(me.getTotalCheckpointDurationMillis());

    assertNull(me.getAverageCheckpointDurationMillis());

    assertNull(me.getLastCheckpointDurationMillis());

    assertNull(me.getLastCheckpointStartTime());

    assertNull(me.getLastCheckpointStopTime());

    assertNull(me.getLastCheckpointTime());

    assertNull(me.getMillisSinceLastCheckpoint());

    assertNull(me.getReadLocksHeld());

    assertNull(me.getWriteLocksHeld());

    assertNull(me.getTransactionsWaitingOnLocks());

    assertNotNull(me.getEnvironmentStats());
    assertEquals(me.getEnvironmentStats().size(), 0);

    assertNull(me.getEnvironmentStat("CacheTotalBytes"));
    assertNull(me.getEnvironmentStat("cachetotalbytes"));
    assertNull(me.getEnvironmentStat("undefined"));

    assertNotNull(me.getLockStats());
    assertEquals(me.getLockStats().size(), 0);

    assertNull(me.getLockStat("NReadLocks"));
    assertNull(me.getLockStat("nreadlocks"));
    assertNull(me.getLockStat("undefined"));

    assertNotNull(me.getTransactionStats());
    assertEquals(me.getTransactionStats().size(), 0);

    assertNull(me.getTransactionStat("NActive"));
    assertNull(me.getTransactionStat("nactive"));
    assertNull(me.getLockStat("undefined"));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());
  }
}
