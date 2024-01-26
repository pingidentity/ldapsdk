/*
 * Copyright 2009-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2024 Ping Identity Corporation
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
 * Copyright (C) 2009-2024 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the ReplicaMonitorEntry class.
 */
  public class ReplicaMonitorEntryTestCase
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
         "dn: cn=Replica dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replica-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replica dc_example_dc_com",
         "base-dn: dc=example,dc=com",
         "connected-to: directory.example.com:8989",
         "lost-connections: 1",
         "received-updates: 2",
         "sent-updates: 3",
         "pending-updates: 4",
         "replayed-updates: 5",
         "replayed-updates-ok: 6",
         "resolved-modify-conflicts: 7",
         "resolved-naming-conflicts: 8",
         "unresolved-naming-conflicts: 9",
         "replica-id: 10",
         "max-rcv-window: 11",
         "current-rcv-window: 12",
         "max-send-window: 13",
         "current-send-window: 14",
         "ssl-encryption: false",
         "generation-id: 15",
         "total-update-count: 16",
         "received-acks: 17",
         "sent-acks: 18",
         "replayed-updates-failed: 19",
         "conflict-entry-count: 20",
         "replication-backlog: 21",
         "age-of-oldest-backlog-change: 20240102010203.456Z",
         "pending-changes-current-uncommitted-size: 22",
         "age-of-oldest-pending-update: 23",
         "pending-changes-max-capacity: 24",
         "pending-changes-largest-size-reached: 25",
         "pending-changes-num-times-added-to-full-queue: 26",
         "pending-changes-num-times-stall-logged: 27",
         "last-update-latency-millis: 28",
         "recent-average-latency-millis: 29",
         "recent-maximum-latency-millis: 30",
         "recent-minimum-latency-millis: 31",
         "recent-negative-latency-update-count: 32",
         "recent-sum-latency-millis: 33",
         "recent-update-count: 34",
         "total-average-latency-millis: 35",
         "total-maximum-latency-millis: 36",
         "total-minimum-latency-millis: 37",
         "total-negative-latency-update-count: 38",
         "total-sum-latency-millis: 39",
         "replication-assurance-submitted-operations: 40",
         "replication-assurance-completed-normally: 41",
         "replication-assurance-completed-abnormally: 42",
         "replication-assurance-completed-with-timeout: 43",
         "replication-assurance-completed-with-shutdown: 44",
         "requeue-retry-op-success-count: 45",
         "requeue-retry-op-failed-count: 46",
         "requeue-retry-add-success-count: 47",
         "requeue-retry-add-failed-count: 48",
         "requeue-retry-delete-success-count: 49",
         "requeue-retry-delete-failed-count: 50",
         "requeue-retry-modify-success-count: 51",
         "requeue-retry-modify-failed-count: 52",
         "requeue-retry-modify-dn-success-count: 53",
         "requeue-retry-modify-dn-failed-count: 54",
         "requeue-retry-op-success-average-duration-millis: 55.5",
         "requeue-retry-op-success-maximum-duration-millis: 56.5",
         "requeue-retry-op-success-total-millis: 57");

    ReplicaMonitorEntry me = new ReplicaMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replica-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicaMonitorEntry.class.getName());

    assertNotNull(me.getBaseDN());
    assertEquals(new DN(me.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(me.getReplicationServerAddress());
    assertEquals(me.getReplicationServerAddress(), "directory.example.com");

    assertNotNull(me.getReplicationServerPort());
    assertEquals(me.getReplicationServerPort(), Long.valueOf(8989L));

    assertNotNull(me.getLostConnections());
    assertEquals(me.getLostConnections(), Long.valueOf(1L));

    assertNotNull(me.getReceivedUpdates());
    assertEquals(me.getReceivedUpdates(), Long.valueOf(2L));

    assertNotNull(me.getSentUpdates());
    assertEquals(me.getSentUpdates(), Long.valueOf(3L));

    assertNotNull(me.getPendingUpdates());
    assertEquals(me.getPendingUpdates(), Long.valueOf(4L));

    assertNotNull(me.getTotalUpdatesReplayed());
    assertEquals(me.getTotalUpdatesReplayed(), Long.valueOf(5L));

    assertNotNull(me.getUpdatesSuccessfullyReplayed());
    assertEquals(me.getUpdatesSuccessfullyReplayed(), Long.valueOf(6L));

    assertNotNull(me.getUpdatesReplayedAfterModifyConflict());
    assertEquals(me.getUpdatesReplayedAfterModifyConflict(), Long.valueOf(7L));

    assertNotNull(me.getUpdatesReplayedAfterNamingConflict());
    assertEquals(me.getUpdatesReplayedAfterNamingConflict(), Long.valueOf(8L));

    assertNotNull(me.getUnresolvedNamingConflicts());
    assertEquals(me.getUnresolvedNamingConflicts(), Long.valueOf(9L));

    assertNotNull(me.getReplicaID());
    assertEquals(me.getReplicaID(), "10");

    assertNotNull(me.getMaximumReceiveWindowSize());
    assertEquals(me.getMaximumReceiveWindowSize(), Long.valueOf(11L));

    assertNotNull(me.getCurrentReceiveWindowSize());
    assertEquals(me.getCurrentReceiveWindowSize(), Long.valueOf(12L));

    assertNotNull(me.getMaximumSendWindowSize());
    assertEquals(me.getMaximumSendWindowSize(), Long.valueOf(13L));

    assertNotNull(me.getCurrentSendWindowSize());
    assertEquals(me.getCurrentSendWindowSize(), Long.valueOf(14L));

    assertNotNull(me.getTotalUpdateCount());
    assertEquals(me.getTotalUpdateCount(), Long.valueOf(16L));

    assertNotNull(me.getReceivedAcks());
    assertEquals(me.getReceivedAcks(), Long.valueOf(17L));

    assertNotNull(me.getSentAcks());
    assertEquals(me.getSentAcks(), Long.valueOf(18L));

    assertNotNull(me.getUpdateReplayFailures());
    assertEquals(me.getUpdateReplayFailures(), Long.valueOf(19L));

    assertNotNull(me.getConflictEntryCount());
    assertEquals(me.getConflictEntryCount(), Long.valueOf(20L));

    assertNotNull(me.getReplicationBacklog());
    assertEquals(me.getReplicationBacklog(), Long.valueOf(21L));

    assertNotNull(me.getOldestBacklogChangeTime());
    assertEquals(me.getOldestBacklogChangeTime(),
         StaticUtils.decodeGeneralizedTime("20240102010203.456Z"));

    assertNotNull(me.getPendingChangesCurrentUncommittedSize());
    assertEquals(me.getPendingChangesCurrentUncommittedSize(),
         Long.valueOf(22L));

    assertNotNull(me.getAgeOfOldestPendingUpdateMillis());
    assertEquals(me.getAgeOfOldestPendingUpdateMillis(), Long.valueOf(23L));

    assertNotNull(me.getPendingChangesMaxCapacity());
    assertEquals(me.getPendingChangesMaxCapacity(), Long.valueOf(24L));

    assertNotNull(me.getPendingChangesLargestSizeReached());
    assertEquals(me.getPendingChangesLargestSizeReached(), Long.valueOf(25L));

    assertNotNull(me.getPendingChangesNumTimesAddedToFullQueue());
    assertEquals(me.getPendingChangesNumTimesAddedToFullQueue(),
         Long.valueOf(26L));

    assertNotNull(me.getPendingChangesNumTimesStallLogged());
    assertEquals(me.getPendingChangesNumTimesStallLogged(), Long.valueOf(27L));

    assertNotNull(me.getLastUpdateLatencyMillis());
    assertEquals(me.getLastUpdateLatencyMillis(), Long.valueOf(28L));

    assertNotNull(me.getRecentAverageLatencyMillis());
    assertEquals(me.getRecentAverageLatencyMillis(), Long.valueOf(29L));

    assertNotNull(me.getRecentMaximumLatencyMillis());
    assertEquals(me.getRecentMaximumLatencyMillis(), Long.valueOf(30L));

    assertNotNull(me.getRecentMinimumLatencyMillis());
    assertEquals(me.getRecentMinimumLatencyMillis(), Long.valueOf(31L));

    assertNotNull(me.getRecentNegativeLatencyUpdateCount());
    assertEquals(me.getRecentNegativeLatencyUpdateCount(), Long.valueOf(32));

    assertNotNull(me.getRecentSumLatencyMillis());
    assertEquals(me.getRecentSumLatencyMillis(), Long.valueOf(33L));

    assertNotNull(me.getRecentUpdateCount());
    assertEquals(me.getRecentUpdateCount(), Long.valueOf(34L));

    assertNotNull(me.getTotalAverageLatencyMillis());
    assertEquals(me.getTotalAverageLatencyMillis(), Long.valueOf(35L));

    assertNotNull(me.getTotalMaximumLatencyMillis());
    assertEquals(me.getTotalMaximumLatencyMillis(), Long.valueOf(36L));

    assertNotNull(me.getTotalMinimumLatencyMillis());
    assertEquals(me.getTotalMinimumLatencyMillis(), Long.valueOf(37L));

    assertNotNull(me.getTotalNegativeLatencyUpdateCount());
    assertEquals(me.getTotalNegativeLatencyUpdateCount(), Long.valueOf(38L));

    assertNotNull(me.getTotalSumLatencyMillis());
    assertEquals(me.getTotalSumLatencyMillis(), Long.valueOf(39L));

    assertNotNull(me.getReplicationAssuranceSubmittedOperations());
    assertEquals(me.getReplicationAssuranceSubmittedOperations(),
         Long.valueOf(40L));

    assertNotNull(me.getReplicationAssuranceCompletedNormally());
    assertEquals(me.getReplicationAssuranceCompletedNormally(),
         Long.valueOf(41L));

    assertNotNull(me.getReplicationAssuranceCompletedAbnormally());
    assertEquals(me.getReplicationAssuranceCompletedAbnormally(),
         Long.valueOf(42L));

    assertNotNull(me.getReplicationAssuranceCompletedWithTimeout());
    assertEquals(me.getReplicationAssuranceCompletedWithTimeout(),
         Long.valueOf(43L));

    assertNotNull(me.getReplicationAssuranceCompletedWithShutdown());
    assertEquals(me.getReplicationAssuranceCompletedWithShutdown(),
         Long.valueOf(44L));

    assertNotNull(me.getRequeueRetryOpSuccessCount());
    assertEquals(me.getRequeueRetryOpSuccessCount(), Long.valueOf(45L));

    assertNotNull(me.getRequeueRetryOpFailedCount());
    assertEquals(me.getRequeueRetryOpFailedCount(), Long.valueOf(46L));

    assertNotNull(me.getRequeueRetryAddSuccessCount());
    assertEquals(me.getRequeueRetryAddSuccessCount(), Long.valueOf(47L));

    assertNotNull(me.getRequeueRetryAddFailedCount());
    assertEquals(me.getRequeueRetryAddFailedCount(), Long.valueOf(48L));

    assertNotNull(me.getRequeueRetryDeleteSuccessCount());
    assertEquals(me.getRequeueRetryDeleteSuccessCount(), Long.valueOf(49L));

    assertNotNull(me.getRequeueRetryDeleteFailedCount());
    assertEquals(me.getRequeueRetryDeleteFailedCount(), Long.valueOf(50L));

    assertNotNull(me.getRequeueRetryModifySuccessCount());
    assertEquals(me.getRequeueRetryModifySuccessCount(), Long.valueOf(51L));

    assertNotNull(me.getRequeueRetryModifyFailedCount());
    assertEquals(me.getRequeueRetryModifyFailedCount(), Long.valueOf(52L));

    assertNotNull(me.getRequeueRetryModifyDNSuccessCount());
    assertEquals(me.getRequeueRetryModifyDNSuccessCount(), Long.valueOf(53L));

    assertNotNull(me.getRequeueRetryModifyDNFailedCount());
    assertEquals(me.getRequeueRetryModifyDNFailedCount(), Long.valueOf(54L));

    assertNotNull(me.getRequeueRetrySuccessAverageDurationMillis());
    assertEquals(me.getRequeueRetrySuccessAverageDurationMillis(),
         Double.valueOf(55.5d));

    assertNotNull(me.getRequeueRetrySuccessMaximumDurationMillis());
    assertEquals(me.getRequeueRetrySuccessMaximumDurationMillis(),
         Double.valueOf(56.5d));

    assertNotNull(me.getRequeueRetrySuccessTotalDurationMillis());
    assertEquals(me.getRequeueRetrySuccessTotalDurationMillis(),
         Long.valueOf(57L));

    assertNotNull(me.useSSL());
    assertEquals(me.useSSL(), Boolean.FALSE);

    assertNotNull(me.getGenerationID());
    assertEquals(me.getGenerationID(), "15");

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("base-dn"));
    assertEquals(new DN(attrs.get("base-dn").getStringValue()),
                 new DN("dc=example,dc=com"));

    assertNotNull(attrs.get("connected-to"));
    assertEquals(attrs.get("connected-to").getStringValue(),
                 "directory.example.com:8989");

    assertNotNull(attrs.get("lost-connections"));
    assertEquals(attrs.get("lost-connections").getLongValue(),
                 Long.valueOf(1L));

    assertNotNull(attrs.get("received-updates"));
    assertEquals(attrs.get("received-updates").getLongValue(),
                 Long.valueOf(2L));

    assertNotNull(attrs.get("sent-updates"));
    assertEquals(attrs.get("sent-updates").getLongValue(),
                 Long.valueOf(3L));

    assertNotNull(attrs.get("pending-updates"));
    assertEquals(attrs.get("pending-updates").getLongValue(),
                 Long.valueOf(4L));

    assertNotNull(attrs.get("replayed-updates"));
    assertEquals(attrs.get("replayed-updates").getLongValue(),
                 Long.valueOf(5L));

    assertNotNull(attrs.get("replayed-updates-ok"));
    assertEquals(attrs.get("replayed-updates-ok").getLongValue(),
                 Long.valueOf(6L));

    assertNotNull(attrs.get("resolved-modify-conflicts"));
    assertEquals(attrs.get("resolved-modify-conflicts").getLongValue(),
                 Long.valueOf(7L));

    assertNotNull(attrs.get("resolved-naming-conflicts"));
    assertEquals(attrs.get("resolved-naming-conflicts").getLongValue(),
                 Long.valueOf(8L));

    assertNotNull(attrs.get("unresolved-naming-conflicts"));
    assertEquals(attrs.get("unresolved-naming-conflicts").getLongValue(),
                 Long.valueOf(9L));

    assertNotNull(attrs.get("replica-id"));
    assertEquals(attrs.get("replica-id").getStringValue(), "10");

    assertNotNull(attrs.get("max-rcv-window"));
    assertEquals(attrs.get("max-rcv-window").getLongValue(), Long.valueOf(11L));

    assertNotNull(attrs.get("current-rcv-window"));
    assertEquals(attrs.get("current-rcv-window").getLongValue(),
                 Long.valueOf(12L));

    assertNotNull(attrs.get("max-send-window"));
    assertEquals(attrs.get("max-send-window").getLongValue(),
                 Long.valueOf(13L));

    assertNotNull(attrs.get("current-send-window"));
    assertEquals(attrs.get("current-send-window").getLongValue(),
                 Long.valueOf(14L));

    assertNotNull(attrs.get("ssl-encryption"));
    assertEquals(attrs.get("ssl-encryption").getBooleanValue(), Boolean.FALSE);

    assertNotNull(attrs.get("generation-id"));
    assertEquals(attrs.get("generation-id").getStringValue(), "15");

    assertNotNull(attrs.get("total-update-count"));
    assertEquals(attrs.get("total-update-count").getLongValue(),
         Long.valueOf(16L));

    assertNotNull(attrs.get("received-acks"));
    assertEquals(attrs.get("received-acks").getLongValue(), Long.valueOf(17L));

    assertNotNull(attrs.get("sent-acks"));
    assertEquals(attrs.get("sent-acks").getLongValue(), Long.valueOf(18L));

    assertNotNull(attrs.get("replayed-updates-failed"));
    assertEquals(attrs.get("replayed-updates-failed").getLongValue(),
         Long.valueOf(19L));

    assertNotNull(attrs.get("conflict-entry-count"));
    assertEquals(attrs.get("conflict-entry-count").getLongValue(),
         Long.valueOf(20L));

    assertNotNull(attrs.get("replication-backlog"));
    assertEquals(attrs.get("replication-backlog").getLongValue(),
         Long.valueOf(21L));

    assertNotNull(attrs.get("age-of-oldest-backlog-change"));
    assertEquals(
         attrs.get("age-of-oldest-backlog-change").getDateValue(),
         StaticUtils.decodeGeneralizedTime("20240102010203.456Z"));

    assertNotNull(attrs.get("pending-changes-current-uncommitted-size"));
    assertEquals(
         attrs.get("pending-changes-current-uncommitted-size").getLongValue(),
         Long.valueOf(22L));

    assertNotNull(attrs.get("age-of-oldest-pending-update"));
    assertEquals(attrs.get("age-of-oldest-pending-update").getLongValue(),
         Long.valueOf(23L));

    assertNotNull(attrs.get("pending-changes-max-capacity"));
    assertEquals(attrs.get("pending-changes-max-capacity").getLongValue(),
         Long.valueOf(24L));

    assertNotNull(attrs.get("pending-changes-largest-size-reached"));
    assertEquals(
         attrs.get("pending-changes-largest-size-reached").getLongValue(),
         Long.valueOf(25L));

    assertNotNull(attrs.get("pending-changes-num-times-added-to-full-queue"));
    assertEquals(
         attrs.get("pending-changes-num-times-added-to-full-queue").
              getLongValue(),
         Long.valueOf(26L));

    assertNotNull(attrs.get("pending-changes-num-times-stall-logged"));
    assertEquals(
         attrs.get("pending-changes-num-times-stall-logged").getLongValue(),
         Long.valueOf(27L));

    assertNotNull(attrs.get("last-update-latency-millis"));
    assertEquals(attrs.get("last-update-latency-millis").getLongValue(),
         Long.valueOf(28L));

    assertNotNull(attrs.get("recent-average-latency-millis"));
    assertEquals(attrs.get("recent-average-latency-millis").getLongValue(),
         Long.valueOf(29L));

    assertNotNull(attrs.get("recent-maximum-latency-millis"));
    assertEquals(attrs.get("recent-maximum-latency-millis").getLongValue(),
         Long.valueOf(30L));

    assertNotNull(attrs.get("recent-minimum-latency-millis"));
    assertEquals(attrs.get("recent-minimum-latency-millis").getLongValue(),
         Long.valueOf(31L));

    assertNotNull(attrs.get("recent-negative-latency-update-count"));
    assertEquals(
         attrs.get("recent-negative-latency-update-count").getLongValue(),
         Long.valueOf(32L));

    assertNotNull(attrs.get("recent-sum-latency-millis"));
    assertEquals(attrs.get("recent-sum-latency-millis").getLongValue(),
         Long.valueOf(33L));

    assertNotNull(attrs.get("recent-update-count"));
    assertEquals(attrs.get("recent-update-count").getLongValue(),
         Long.valueOf(34L));

    assertNotNull(attrs.get("total-average-latency-millis"));
    assertEquals(attrs.get("total-average-latency-millis").getLongValue(),
         Long.valueOf(35L));

    assertNotNull(attrs.get("total-maximum-latency-millis"));
    assertEquals(attrs.get("total-maximum-latency-millis").getLongValue(),
         Long.valueOf(36L));

    assertNotNull(attrs.get("total-minimum-latency-millis"));
    assertEquals(attrs.get("total-minimum-latency-millis").getLongValue(),
         Long.valueOf(37L));

    assertNotNull(attrs.get("total-negative-latency-update-count"));
    assertEquals(
         attrs.get("total-negative-latency-update-count").getLongValue(),
         Long.valueOf(38L));

    assertNotNull(attrs.get("total-sum-latency-millis"));
    assertEquals(attrs.get("total-sum-latency-millis").getLongValue(),
         Long.valueOf(39L));

    assertNotNull(attrs.get("replication-assurance-submitted-operations"));
    assertEquals(
         attrs.get("replication-assurance-submitted-operations").getLongValue(),
         Long.valueOf(40L));

    assertNotNull(attrs.get("replication-assurance-completed-normally"));
    assertEquals(
         attrs.get("replication-assurance-completed-normally").getLongValue(),
         Long.valueOf(41L));

    assertNotNull(attrs.get("replication-assurance-completed-abnormally"));
    assertEquals(
         attrs.get("replication-assurance-completed-abnormally").getLongValue(),
         Long.valueOf(42L));

    assertNotNull(attrs.get("replication-assurance-completed-with-timeout"));
    assertEquals(
         attrs.get("replication-assurance-completed-with-timeout")
              .getLongValue(),
         Long.valueOf(43L));

    assertNotNull(attrs.get("replication-assurance-completed-with-shutdown"));
    assertEquals(
         attrs.get("replication-assurance-completed-with-shutdown")
              .getLongValue(),
         Long.valueOf(44L));

    assertNotNull(attrs.get("requeue-retry-op-success-count"));
    assertEquals(attrs.get("requeue-retry-op-success-count").getLongValue(),
         Long.valueOf(45L));

    assertNotNull(attrs.get("requeue-retry-op-failed-count"));
    assertEquals(attrs.get("requeue-retry-op-failed-count").getLongValue(),
         Long.valueOf(46L));

    assertNotNull(attrs.get("requeue-retry-add-success-count"));
    assertEquals(attrs.get("requeue-retry-add-success-count").getLongValue(),
         Long.valueOf(47L));

    assertNotNull(attrs.get("requeue-retry-add-failed-count"));
    assertEquals(attrs.get("requeue-retry-add-failed-count").getLongValue(),
         Long.valueOf(48L));

    assertNotNull(attrs.get("requeue-retry-delete-success-count"));
    assertEquals(attrs.get("requeue-retry-delete-success-count").getLongValue(),
         Long.valueOf(49L));

    assertNotNull(attrs.get("requeue-retry-delete-failed-count"));
    assertEquals(attrs.get("requeue-retry-delete-failed-count").getLongValue(),
         Long.valueOf(50L));

    assertNotNull(attrs.get("requeue-retry-modify-success-count"));
    assertEquals(attrs.get("requeue-retry-modify-success-count").getLongValue(),
         Long.valueOf(51L));

    assertNotNull(attrs.get("requeue-retry-modify-failed-count"));
    assertEquals(attrs.get("requeue-retry-modify-failed-count").getLongValue(),
         Long.valueOf(52L));

    assertNotNull(attrs.get("requeue-retry-modify-dn-success-count"));
    assertEquals(attrs.get("requeue-retry-modify-dn-success-count").
              getLongValue(),
         Long.valueOf(53L));

    assertNotNull(attrs.get("requeue-retry-modify-dn-failed-count"));
    assertEquals(attrs.get("requeue-retry-modify-dn-failed-count").
              getLongValue(),
         Long.valueOf(54L));

    assertNotNull(
         attrs.get("requeue-retry-op-success-average-duration-millis"));
    assertEquals(
         attrs.get("requeue-retry-op-success-average-duration-millis").
              getDoubleValue(),
         Double.valueOf(55.5d));

    assertNotNull(
         attrs.get("requeue-retry-op-success-maximum-duration-millis"));
    assertEquals(
         attrs.get("requeue-retry-op-success-maximum-duration-millis").
              getDoubleValue(),
         Double.valueOf(56.5d));

    assertNotNull(attrs.get("requeue-retry-op-success-total-millis"));
    assertEquals(
         attrs.get("requeue-retry-op-success-total-millis").getLongValue(),
         Long.valueOf(57L));
  }



  /**
   * Provides test coverage for the constructor with an entry with an invalid
   * replication server address:port combination.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorInvalidHostPort()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Replica dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replica-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replica dc_example_dc_com",
         "connected-to: invalid");

    ReplicaMonitorEntry me = new ReplicaMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replica-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicaMonitorEntry.class.getName());

    assertNull(me.getBaseDN());

    assertNull(me.getReplicationServerAddress());

    assertNull(me.getReplicationServerPort());

    assertNull(me.getLostConnections());

    assertNull(me.getReceivedUpdates());

    assertNull(me.getSentUpdates());

    assertNull(me.getPendingUpdates());

    assertNull(me.getTotalUpdatesReplayed());

    assertNull(me.getUpdatesSuccessfullyReplayed());

    assertNull(me.getUpdatesReplayedAfterModifyConflict());

    assertNull(me.getUpdatesReplayedAfterNamingConflict());

    assertNull(me.getUnresolvedNamingConflicts());

    assertNull(me.getReplicaID());

    assertNull(me.getMaximumReceiveWindowSize());

    assertNull(me.getCurrentReceiveWindowSize());

    assertNull(me.getMaximumSendWindowSize());

    assertNull(me.getCurrentSendWindowSize());

    assertNull(me.useSSL());

    assertNull(me.getGenerationID());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());
  }



  /**
   * Provides test coverage for the constructor with an entry with an invalid
   * port number for the replication server address:port combination.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorInvalidPort()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Replica dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replica-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replica dc_example_dc_com",
         "connected-to: invalid:invalid");

    ReplicaMonitorEntry me = new ReplicaMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replica-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicaMonitorEntry.class.getName());

    assertNull(me.getBaseDN());

    assertNull(me.getReplicationServerAddress());

    assertNull(me.getReplicationServerPort());

    assertNull(me.getLostConnections());

    assertNull(me.getReceivedUpdates());

    assertNull(me.getSentUpdates());

    assertNull(me.getPendingUpdates());

    assertNull(me.getTotalUpdatesReplayed());

    assertNull(me.getUpdatesSuccessfullyReplayed());

    assertNull(me.getUpdatesReplayedAfterModifyConflict());

    assertNull(me.getUpdatesReplayedAfterNamingConflict());

    assertNull(me.getUnresolvedNamingConflicts());

    assertNull(me.getReplicaID());

    assertNull(me.getMaximumReceiveWindowSize());

    assertNull(me.getCurrentReceiveWindowSize());

    assertNull(me.getMaximumSendWindowSize());

    assertNull(me.getCurrentSendWindowSize());

    assertNull(me.useSSL());

    assertNull(me.getGenerationID());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());
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
         "dn: cn=Replica dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replica-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replica dc_example_dc_com");

    ReplicaMonitorEntry me = new ReplicaMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replica-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicaMonitorEntry.class.getName());

    assertNull(me.getBaseDN());

    assertNull(me.getReplicationServerAddress());

    assertNull(me.getReplicationServerPort());

    assertNull(me.getLostConnections());

    assertNull(me.getReceivedUpdates());

    assertNull(me.getSentUpdates());

    assertNull(me.getPendingUpdates());

    assertNull(me.getTotalUpdatesReplayed());

    assertNull(me.getUpdatesSuccessfullyReplayed());

    assertNull(me.getUpdatesReplayedAfterModifyConflict());

    assertNull(me.getUpdatesReplayedAfterNamingConflict());

    assertNull(me.getUnresolvedNamingConflicts());

    assertNull(me.getReplicaID());

    assertNull(me.getMaximumReceiveWindowSize());

    assertNull(me.getCurrentReceiveWindowSize());

    assertNull(me.getMaximumSendWindowSize());

    assertNull(me.getCurrentSendWindowSize());

    assertNull(me.getTotalUpdateCount());

    assertNull(me.getReceivedAcks());

    assertNull(me.getSentAcks());

    assertNull(me.getUpdateReplayFailures());

    assertNull(me.getConflictEntryCount());

    assertNull(me.getReplicationBacklog());

    assertNull(me.getOldestBacklogChangeTime());

    assertNull(me.getPendingChangesCurrentUncommittedSize());

    assertNull(me.getAgeOfOldestPendingUpdateMillis());

    assertNull(me.getPendingChangesMaxCapacity());

    assertNull(me.getPendingChangesLargestSizeReached());

    assertNull(me.getPendingChangesNumTimesAddedToFullQueue());

    assertNull(me.getPendingChangesNumTimesStallLogged());

    assertNull(me.getLastUpdateLatencyMillis());

    assertNull(me.getRecentAverageLatencyMillis());

    assertNull(me.getRecentMaximumLatencyMillis());

    assertNull(me.getRecentMinimumLatencyMillis());

    assertNull(me.getRecentNegativeLatencyUpdateCount());

    assertNull(me.getRecentSumLatencyMillis());

    assertNull(me.getRecentUpdateCount());

    assertNull(me.getTotalAverageLatencyMillis());

    assertNull(me.getTotalMaximumLatencyMillis());

    assertNull(me.getTotalMinimumLatencyMillis());

    assertNull(me.getTotalNegativeLatencyUpdateCount());

    assertNull(me.getTotalSumLatencyMillis());

    assertNull(me.getReplicationAssuranceSubmittedOperations());

    assertNull(me.getReplicationAssuranceCompletedNormally());

    assertNull(me.getReplicationAssuranceCompletedAbnormally());

    assertNull(me.getReplicationAssuranceCompletedWithTimeout());

    assertNull(me.getReplicationAssuranceCompletedWithShutdown());

    assertNull(me.getRequeueRetryOpSuccessCount());

    assertNull(me.getRequeueRetryOpFailedCount());

    assertNull(me.getRequeueRetryAddSuccessCount());

    assertNull(me.getRequeueRetryAddFailedCount());

    assertNull(me.getRequeueRetryDeleteSuccessCount());

    assertNull(me.getRequeueRetryDeleteFailedCount());

    assertNull(me.getRequeueRetryModifySuccessCount());

    assertNull(me.getRequeueRetryModifyFailedCount());

    assertNull(me.getRequeueRetryModifyDNSuccessCount());

    assertNull(me.getRequeueRetryModifyDNFailedCount());

    assertNull(me.getRequeueRetrySuccessAverageDurationMillis());

    assertNull(me.getRequeueRetrySuccessMaximumDurationMillis());

    assertNull(me.getRequeueRetrySuccessTotalDurationMillis());

    assertNull(me.useSSL());

    assertNull(me.getGenerationID());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());
  }
}
