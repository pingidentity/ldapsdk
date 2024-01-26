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



import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the state
 * of a replica, including the base DN, replica ID, and generation ID, as well
 * as information about its communication with the replication server
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The server should present a replica monitor entry for each replicated base
 * DN.  They can be retrieved using the
 * {@link MonitorManager#getReplicaMonitorEntries} method.  These entries
 * provide specific methods for accessing information about the replica.
 * Alternately, this information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReplicaMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in replica monitor entries.
   */
  @NotNull static final String REPLICA_MONITOR_OC =
       "ds-replica-monitor-entry";



  /**
   * The name of the attribute that holds the age, in milliseconds, of the
   * oldest operation in the pending changes queue.
   */
  @NotNull private static final String
       ATTR_AGE_OF_OLDEST_PENDING_UPDATE_MILLIS =
            "age-of-oldest-pending-update";



  /**
   * The name of the attribute that contains the base DN for the replicated
   * data.
   */
  @NotNull private static final String ATTR_BASE_DN = "base-dn";



  /**
   * The name of the attribute that contains the number of conflict entries
   * that currently exist in the associated backend.
   */
  @NotNull private static final String ATTR_CONFLICT_ENTRY_COUNT =
       "conflict-entry-count";



  /**
   * The name of the attribute that contains the address and port of the
   * replication server to which the replica is connected.
   */
  @NotNull private static final String ATTR_CONNECTED_TO =
       "connected-to";



  /**
   * The name of the attribute that provides information about the current
   * receive window size.
   */
  @NotNull private static final String ATTR_CURRENT_RECEIVE_WINDOW_SIZE =
       "current-rcv-window";



  /**
   * The name of the attribute that provides information about the current send
   * window size.
   */
  @NotNull private static final String ATTR_CURRENT_SEND_WINDOW_SIZE =
       "current-send-window";



  /**
   * The name of the attribute that contains the number of failures that
   * occurred while attempting to replay changes.
   */
  @NotNull private static final String ATTR_FAILED_REPLAYED =
       "replayed-updates-failed";



  /**
   * The name of the attribute that provides the generation ID for the replica.
   */
  @NotNull private static final String ATTR_GENERATION_ID = "generation-id";



  /**
   * The name of the attribute that holds the latency, in milliseconds, of the
   * last update that was successfully replayed.
   */
  @NotNull private static final String ATTR_LAST_UPDATE_LATENCY_MILLIS =
       "last-update-latency-millis";



  /**
   * The name of the attribute that provides information about the number of
   * times the connection to the replication server has been lost.
   */
  @NotNull private static final String ATTR_LOST_CONNECTIONS =
       "lost-connections";



  /**
   * The name of the attribute that provides information about the maximum
   * receive window size.
   */
  @NotNull private static final String ATTR_MAX_RECEIVE_WINDOW_SIZE =
       "max-rcv-window";



  /**
   * The name of the attribute that provides information about the maximum send
   * window size.
   */
  @NotNull private static final String ATTR_MAX_SEND_WINDOW_SIZE =
       "max-send-window";



  /**
   * The name of the attribute that holds a generalized time representation of
   * the time that the oldest change was applied in another server but has not
   * yet replicated to the local server.
   */
  @NotNull private static final String ATTR_OLDEST_BACKLOG_CHANGE_TIME =
       "age-of-oldest-backlog-change";



  /**
   * The name of the attribute that contains the number of changes in the
   * pending change queue that have not yet been committed to the database.
   */
  @NotNull private static final String
       ATTR_PENDING_CHANGES_CURRENT_UNCOMMITTED_SIZE =
            "pending-changes-current-uncommitted-size";



  /**
   * The name of the attribute that contains the maximum number of changes that
   * have been in the pending changes queue at any time.
   */
  @NotNull private static final String
       ATTR_PENDING_CHANGES_LARGEST_SIZE_REACHED =
            "pending-changes-largest-size-reached";



  /**
   * The name of the attribute that contains the maximum allowed size of the
   * pending changes queue.
   */
  @NotNull private static final String ATTR_PENDING_CHANGES_MAX_CAPACITY =
       "pending-changes-max-capacity";



  /**
   * The name of the attribute that contains the number of times that the server
   * has attempted to add a change to the pending changes queue when it was
   * already full.
   */
  @NotNull private static final String
       ATTR_PENDING_CHANGES_NUM_TIMES_ADDED_TO_FULL_QUEUE =
            "pending-changes-num-times-added-to-full-queue";



  /**
   * The name of the attribute that contains the number of times that the server
   * has logged that an operation in the pending changes queue has stalled.
   */
  @NotNull private static final String
       ATTR_PENDING_CHANGES_NUM_TIMES_STALL_LOGGED =
            "pending-changes-num-times-stall-logged";



  /**
   * The name of the attribute that contains the number of pending updates which
   * are currently being processed by the Directory Server and have not yet been
   * sent to the replication server.
   */
  @NotNull private static final String ATTR_PENDING_UPDATES = "pending-updates";



  /**
   * The name of the attribute that contains the number of acknowledgements
   * received from the replication server for this replica.
   */
  @NotNull private static final String ATTR_RECEIVED_ACKS = "received-acks";



  /**
   * The name of the attribute that contains the number of updates received from
   * the replication server for this replica.
   */
  @NotNull private static final String ATTR_RECEIVED_UPDATES =
       "received-updates";



  /**
   * The name of the attribute that contains the average replication latency, in
   * milliseconds, for operations processed over a recent interval.
   */
  @NotNull private static final String ATTR_RECENT_AVERAGE_LATENCY_MILLIS =
       "recent-average-latency-millis";



  /**
   * The name of the attribute that contains the maximum replication latency, in
   * milliseconds, for any operation processed over a recent interval.
   */
  @NotNull private static final String ATTR_RECENT_MAXIMUM_LATENCY_MILLIS =
       "recent-maximum-latency-millis";



  /**
   * The name of the attribute that contains the minimum replication latency, in
   * milliseconds, for any operation processed over a recent interval.
   */
  @NotNull private static final String ATTR_RECENT_MINIMUM_LATENCY_MILLIS =
       "recent-minimum-latency-millis";



  /**
   * The name of the attribute that contains the number of negative replication
   * latencies encountered over a recent interval.
   */
  @NotNull private static final String
       ATTR_RECENT_NEGATIVE_LATENCY_UPDATE_COUNT =
            "recent-negative-latency-update-count";



  /**
   * The name of the attribute that contains the sum of the replication
   * latencies, in milliseconds, for operations processed over a recent
   * interval.
   */
  @NotNull private static final String ATTR_RECENT_SUM_LATENCY_MILLIS =
       "recent-sum-latency-millis";



  /**
   * The name of the attribute that contains the number of operations processed
   * over a recent interval.
   */
  @NotNull private static final String ATTR_RECENT_UPDATE_COUNT =
       "recent-update-count";



  /**
   * The name of the attribute that provides the replica ID for this replica.
   */
  @NotNull private static final String ATTR_REPLICA_ID = "replica-id";



  /**
   * The name of the attribute that contains the number of changes that were
   * processed with replication assurance but for which assurance could not be
   * guaranteed for some reason.
   */
  @NotNull private static final String
       ATTR_REPLICATION_ASSURANCE_COMPLETED_ABNORMALLY =
       "replication-assurance-completed-abnormally";



  /**
   * The name of the attribute that contains the number of changes that were
   * processed with replication assurance and completed successfully within the
   * assurance constraints.
   */
  @NotNull private static final String
       ATTR_REPLICATION_ASSURANCE_COMPLETED_NORMALLY =
       "replication-assurance-completed-normally";



  /**
   * The name of the attribute that contains the number of changes that were
   * processed with replication assurance, but one of the target servers was
   * shut down before assurance could be guaranteed.
   */
  @NotNull private static final String
       ATTR_REPLICATION_ASSURANCE_COMPLETED_WITH_SHUTDOWN =
       "replication-assurance-completed-with-shutdown";



  /**
   * The name of the attribute that contains the number of changes that were
   * processed with replication assurance, but a timeout was encountered before
   * assurance could be guaranteed.
   */
  @NotNull private static final String
       ATTR_REPLICATION_ASSURANCE_COMPLETED_WITH_TIMEOUT =
       "replication-assurance-completed-with-timeout";



  /**
   * The name of the attribute that contains the number of changes that have
   * begun processing with replication assurance enabled.
   */
  @NotNull private static final String
       ATTR_REPLICATION_ASSURANCE_SUBMITTED_OPERATIONS =
       "replication-assurance-submitted-operations";



  /**
   * The name of the attribute that contains the number of changes that have
   * been applied in other servers but have not yet been replicated to the
   * local server.
   */
  @NotNull private static final String ATTR_REPLICATION_BACKLOG =
       "replication-backlog";



  /**
   * The name of the attribute that contains number of requeued add operations
   * that failed on a retry attempt.
   */
  @NotNull private static final String ATTR_REQUEUE_RETRY_ADD_FAILED_COUNT =
       "requeue-retry-add-failed-count";



  /**
   * The name of the attribute that contains number of requeued add operations
   * that succeeded on a retry attempt.
   */
  @NotNull private static final String ATTR_REQUEUE_RETRY_ADD_SUCCESS_COUNT =
       "requeue-retry-add-success-count";



  /**
   * The name of the attribute that contains number of requeued delete
   * operations that failed on a retry attempt.
   */
  @NotNull private static final String ATTR_REQUEUE_RETRY_DELETE_FAILED_COUNT =
       "requeue-retry-delete-failed-count";



  /**
   * The name of the attribute that contains number of requeued delete
   * operations that succeeded on a retry attempt.
   */
  @NotNull private static final String ATTR_REQUEUE_RETRY_DELETE_SUCCESS_COUNT =
       "requeue-retry-delete-success-count";



  /**
   * The name of the attribute that contains number of requeued modify DN
   * operations that failed on a retry attempt.
   */
  @NotNull private static final String
       ATTR_REQUEUE_RETRY_MODIFY_DN_FAILED_COUNT =
            "requeue-retry-modify-dn-failed-count";



  /**
   * The name of the attribute that contains number of requeued modify DN
   * operations that succeeded on a retry attempt.
   */
  @NotNull private static final String
       ATTR_REQUEUE_RETRY_MODIFY_DN_SUCCESS_COUNT =
            "requeue-retry-modify-dn-success-count";



  /**
   * The name of the attribute that contains number of requeued modify
   * operations that failed on a retry attempt.
   */
  @NotNull private static final String ATTR_REQUEUE_RETRY_MODIFY_FAILED_COUNT =
       "requeue-retry-modify-failed-count";



  /**
   * The name of the attribute that contains number of requeued modify
   * operations that succeeded on a retry attempt.
   */
  @NotNull private static final String ATTR_REQUEUE_RETRY_MODIFY_SUCCESS_COUNT =
       "requeue-retry-modify-success-count";



  /**
   * The name of the attribute that contains number of requeued operations that
   * failed on a retry attempt.
   */
  @NotNull private static final String ATTR_REQUEUE_RETRY_OP_FAILED_COUNT =
       "requeue-retry-op-failed-count";



  /**
   * The name of the attribute that contains number of requeued operations that
   * succeeded on a retry attempt.
   */
  @NotNull private static final String ATTR_REQUEUE_RETRY_OP_SUCCESS_COUNT =
       "requeue-retry-op-success-count";



  /**
   * The name of the attribute that contains average length of time in
   * milliseconds required to successfully retry operations that had been
   * requeued.
   */
  @NotNull private static final String
       ATTR_REQUEUE_RETRY_OP_SUCCESS_AVERAGE_DURATION_MILLIS =
            "requeue-retry-op-success-average-duration-millis";



  /**
   * The name of the attribute that contains maximum length of time in
   * milliseconds required to successfully retry any operation that had been
   * requeued.
   */
  @NotNull private static final String
       ATTR_REQUEUE_RETRY_OP_SUCCESS_MAXIMUM_DURATION_MILLIS =
            "requeue-retry-op-success-maximum-duration-millis";



  /**
   * The name of the attribute that contains total length of time in
   * milliseconds required to successfully retry operations that had been
   * requeued.
   */
  @NotNull private static final String
       ATTR_REQUEUE_RETRY_OP_SUCCESS_TOTAL_DURATION_MILLIS =
            "requeue-retry-op-success-total-millis";



  /**
   * The name of the attribute that provides information about the number of
   * updates that were replayed after resolving a modify conflict.
   */
  @NotNull private static final String ATTR_RESOLVED_MODIFY_CONFLICTS =
       "resolved-modify-conflicts";



  /**
   * The name of the attribute that provides information about the number of
   * updates that were replayed after resolving a naming conflict.
   */
  @NotNull private static final String ATTR_RESOLVED_NAMING_CONFLICTS =
       "resolved-naming-conflicts";



  /**
   * The name of the attribute that contains the number of acknowledgements sent
   * from the replication server from this replica.
   */
  @NotNull private static final String ATTR_SENT_ACKS = "sent-acks";



  /**
   * The name of the attribute that provides information about the number of
   * updates sent to the replication server from this replica.
   */
  @NotNull private static final String ATTR_SENT_UPDATES = "sent-updates";



  /**
   * The name of the attribute that indicates whether SSL is used when
   * communicating with the replication server.
   */
  @NotNull private static final String ATTR_SSL_ENCRYPTION = "ssl-encryption";



  /**
   * The name of the attribute that provides information about the number of
   * updates that have been successfully replayed with no problems.
   */
  @NotNull private static final String ATTR_SUCCESSFUL_REPLAYED =
       "replayed-updates-ok";



  /**
   * The name of the attribute that contains the average replication latency, in
   * milliseconds, for operations processed since the server started.
   */
  @NotNull private static final String ATTR_TOTAL_AVERAGE_LATENCY_MILLIS =
       "total-average-latency-millis";



  /**
   * The name of the attribute that contains the maximum replication latency, in
   * milliseconds, for any operation since the server started.
   */
  @NotNull private static final String ATTR_TOTAL_MAXIMUM_LATENCY_MILLIS =
       "total-maximum-latency-millis";



  /**
   * The name of the attribute that contains the minimum replication latency, in
   * milliseconds, for any operation since the server started.
   */
  @NotNull private static final String ATTR_TOTAL_MINIMUM_LATENCY_MILLIS =
       "total-minimum-latency-millis";



  /**
   * The name of the attribute that contains the number of negative replication
   * latencies encountered since the server stared.
   */
  @NotNull private static final String
       ATTR_TOTAL_NEGATIVE_LATENCY_UPDATE_COUNT =
            "total-negative-latency-update-count";



  /**
   * The name of the attribute that provides information about the total number
   * of updates that have been replayed in some form.
   */
  @NotNull private static final String ATTR_TOTAL_REPLAYED = "replayed-updates";



  /**
   * The name of the attribute that contains the sum of replication latencies,
   * in milliseconds, for operations processed since the server started.
   */
  @NotNull private static final String ATTR_TOTAL_SUM_LATENCY_MILLIS =
       "total-sum-latency-millis";



  /**
   * The name of the attribute that contains the total number of replicated
   * operations processed since the server stared.
   */
  @NotNull private static final String ATTR_TOTAL_UPDATE_COUNT =
       "total-update-count";



  /**
   * The name of the attribute that provides information about the number of
   * updates that could not be replayed because of an unresolved naming
   * conflict.
   */
  @NotNull private static final String ATTR_UNRESOLVED_NAMING_CONFLICTS =
       "unresolved-naming-conflicts";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2327746532075017532L;



  // Indicates whether the replica uses SSL when communicating with the
  // replication server.
  @Nullable private final Boolean useSSL;

  // The time that the oldest backlog change was originally processed.
  @Nullable private final Date oldestBacklogChangeTime;

  // The average duration, in milliseconds, required to process an operation on
  // a successful retry attempt.
  @Nullable private final Double requeueRetrySuccessAverageDurationMillis;

  // The maximum duration, in milliseconds, required to process an operation on
  // a successful retry attempt.
  @Nullable private final Double requeueRetrySuccessMaximumDurationMillis;

  // The age of the oldest pending update, in milliseconds.
  @Nullable private final Long ageOfOldestPendingUpdateMillis;

  // The number of conflict entries currently in the associated backend.
  @Nullable private final Long conflictEntryCount;

  // The current receive window size.
  @Nullable private final Long currentReceiveWindowSize;

  // The current send window size.
  @Nullable private final Long currentSendWindowSize;

  // The number of updates that could not be replayed successfully.
  @Nullable private final Long failedReplayed;

  // The last update latency, in milliseconds.
  @Nullable private final Long lastUpdateLatencyMillis;

  // The number of lost connections.
  @Nullable private final Long lostConnections;

  // The maximum receive window size.
  @Nullable private final Long maxReceiveWindowSize;

  // The maximum send window size.
  @Nullable private final Long maxSendWindowSize;

  // The number of pending changes that have not yet been committed.
  @Nullable private final Long pendingChangesCurrentUncommittedSize;

  // The largest size of the pending changes queue.
  @Nullable private final Long pendingChangesLargestSizeReached;

  // The maximum capacity of the pending changes queue.
  @Nullable private final Long pendingChangesMaxCapacity;

  // The number of attempts to add to a full pending changes queue.
  @Nullable private final Long pendingChangesNumTimesAddedToFullQueue;

  // The number of times the server logged that an operation in the pending
  // changes queue has stalled.
  @Nullable private final Long pendingChangesNumTimesStallLogged;

  // The number of pending updates that haven't been sent to the replication
  // server.
  @Nullable private final Long pendingUpdates;

  // The number of acknowledgements received from the replication server.
  @Nullable private final Long receivedAcks;

  // The number of updates received from the replication server.
  @Nullable private final Long receivedUpdates;

  // The recent average replication latency, in milliseconds.
  @Nullable private final Long recentAverageLatencyMillis;

  // The recent maximum replication latency, in milliseconds.
  @Nullable private final Long recentMaximumLatencyMillis;

  // The recent minimum replication latency, in milliseconds.
  @Nullable private final Long recentMinimumLatencyMillis;

  // The recent negative replication latency count.
  @Nullable private final Long recentNegativeLatencyUpdateCount;

  // The sum of replication latencies for recent updates applied.
  @Nullable private final Long recentSumLatencyMillis;

  // The number of replication updates applied over a recent interval.
  @Nullable private final Long recentUpdateCount;

  // The number of updates replayed after resolving a modify conflict.
  @Nullable private final Long replayedAfterModifyConflict;

  // The number of updates replayed after resolving a naming conflict.
  @Nullable private final Long replayedAfterNamingConflict;

  // The number of changes for which requested replication assurance could not
  // be guaranteed.
  @Nullable private final Long replicationAssuranceCompletedAbnormally;

  // The number of changes for which requested replication assurance was
  // achieved.
  @Nullable private final Long replicationAssuranceCompletedNormally;

  // The number of changes for which requested replication assurance could not
  // be guarnateed because it was interrupted by a server shutdown.
  @Nullable private final Long replicationAssuranceCompletedWithShutdown;

  // The number of changes for which requested replication assurance could not
  // be guarnateed because a timeout was encountered.
  @Nullable private final Long replicationAssuranceCompletedWithTimeout;

  // The number of changes for which requested replication assurance has been
  // requested.
  @Nullable private final Long replicationAssuranceSubmittedOperations;

  // The number of changes that have been applied in other servers but have not
  // yet been replicated to the local server.
  @Nullable private final Long replicationBacklog;

  // The port number of the replication server.
  @Nullable private final Long replicationServerPort;

  // The number of add operations that failed after being retried.
  @Nullable private final Long requeueRetryAddFailedCount;

  // The number of add operations that succeeded after being retried.
  @Nullable private final Long requeueRetryAddSuccessCount;

  // The number of delete operations that failed after being retried.
  @Nullable private final Long requeueRetryDeleteFailedCount;

  // The number of delete operations that succeeded after being retried.
  @Nullable private final Long requeueRetryDeleteSuccessCount;

  // The number of modify DN operations that failed after being retried.
  @Nullable private final Long requeueRetryModifyDNFailedCount;

  // The number of modify DN operations that succeeded after being retried.
  @Nullable private final Long requeueRetryModifyDNSuccessCount;

  // The number of modify operations that failed after being retried.
  @Nullable private final Long requeueRetryModifyFailedCount;

  // The number of modify operations that succeeded after being retried.
  @Nullable private final Long requeueRetryModifySuccessCount;

  // The total number of operations that failed after being retried.
  @Nullable private final Long requeueRetryOpFailedCount;

  // The total number of operations that succeeded after being retried.
  @Nullable private final Long requeueRetryOpSuccessCount;

  // The total length of time in milliseconds required to successfully process
  // retried operations.
  @Nullable private final Long requeueRetrySuccessTotalDurationMillis;

  // The number of acknowledgements sent to the replication server.
  @Nullable private final Long sentAcks;

  // The number of updates sent to the replication server.
  @Nullable private final Long sentUpdates;

  // The number of updates replayed successfully.
  @Nullable private final Long successfullyReplayed;

  // The overall average latency for replicated operations.
  @Nullable private final Long totalAverageLatencyMillis;

  // The maximum latency for any replicated operations.
  @Nullable private final Long totalMaximumLatencyMillis;

  // The minimum latency for any replicated operations.
  @Nullable private final Long totalMinimumLatencyMillis;

  // The total number of negative replication latencies encountered.
  @Nullable private final Long totalNegativeLatencyUpdateCount;

  // The total number of updates replayed.
  @Nullable private final Long totalReplayed;

  // The total duration of all replication latencies, in milliseconds.
  @Nullable private final Long totalSumLatencyMillis;

  // The total number of updates applied via replication.
  @Nullable private final Long totalUpdateCount;

  // The number of unresolved naming conflicts that could not be successfully
  // replayed.
  @Nullable private final Long unresolvedNamingConflicts;

  // The base DN for the replicated data.
  @Nullable private final String baseDN;

  // The generation ID for the replicated data.
  @Nullable private final String generationID;

  // The replica ID for the replica.
  @Nullable private final String replicaID;

  // The address of the replication server.
  @Nullable private final String replicationServerAddress;



  /**
   * Creates a new replica monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a replica monitor entry.  It must
   *                not be {@code null}.
   */
  public ReplicaMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    useSSL = getBoolean(ATTR_SSL_ENCRYPTION);
    oldestBacklogChangeTime = getDate(ATTR_OLDEST_BACKLOG_CHANGE_TIME);
    requeueRetrySuccessAverageDurationMillis =
         getDouble(ATTR_REQUEUE_RETRY_OP_SUCCESS_AVERAGE_DURATION_MILLIS);
    requeueRetrySuccessMaximumDurationMillis =
         getDouble(ATTR_REQUEUE_RETRY_OP_SUCCESS_MAXIMUM_DURATION_MILLIS);
    ageOfOldestPendingUpdateMillis =
         getLong(ATTR_AGE_OF_OLDEST_PENDING_UPDATE_MILLIS);
    conflictEntryCount = getLong(ATTR_CONFLICT_ENTRY_COUNT);
    currentReceiveWindowSize = getLong(ATTR_CURRENT_RECEIVE_WINDOW_SIZE);
    currentSendWindowSize = getLong(ATTR_CURRENT_SEND_WINDOW_SIZE);
    failedReplayed = getLong(ATTR_FAILED_REPLAYED);
    lastUpdateLatencyMillis = getLong(ATTR_LAST_UPDATE_LATENCY_MILLIS);
    lostConnections = getLong(ATTR_LOST_CONNECTIONS);
    maxReceiveWindowSize = getLong(ATTR_MAX_RECEIVE_WINDOW_SIZE);
    maxSendWindowSize = getLong(ATTR_MAX_SEND_WINDOW_SIZE);
    pendingChangesCurrentUncommittedSize =
         getLong(ATTR_PENDING_CHANGES_CURRENT_UNCOMMITTED_SIZE);
    pendingChangesLargestSizeReached =
         getLong(ATTR_PENDING_CHANGES_LARGEST_SIZE_REACHED);
    pendingChangesMaxCapacity = getLong(ATTR_PENDING_CHANGES_MAX_CAPACITY);
    pendingChangesNumTimesAddedToFullQueue =
         getLong(ATTR_PENDING_CHANGES_NUM_TIMES_ADDED_TO_FULL_QUEUE);
    pendingChangesNumTimesStallLogged =
         getLong(ATTR_PENDING_CHANGES_NUM_TIMES_STALL_LOGGED);
    pendingUpdates = getLong(ATTR_PENDING_UPDATES);
    receivedAcks = getLong(ATTR_RECEIVED_ACKS);
    receivedUpdates = getLong(ATTR_RECEIVED_UPDATES);
    recentAverageLatencyMillis = getLong(ATTR_RECENT_AVERAGE_LATENCY_MILLIS);
    recentMaximumLatencyMillis = getLong(ATTR_RECENT_MAXIMUM_LATENCY_MILLIS);
    recentMinimumLatencyMillis = getLong(ATTR_RECENT_MINIMUM_LATENCY_MILLIS);
    recentNegativeLatencyUpdateCount =
         getLong(ATTR_RECENT_NEGATIVE_LATENCY_UPDATE_COUNT);
    recentSumLatencyMillis = getLong(ATTR_RECENT_SUM_LATENCY_MILLIS);
    recentUpdateCount = getLong(ATTR_RECENT_UPDATE_COUNT);
    replayedAfterModifyConflict = getLong(ATTR_RESOLVED_MODIFY_CONFLICTS);
    replayedAfterNamingConflict = getLong(ATTR_RESOLVED_NAMING_CONFLICTS);
    replicationAssuranceCompletedAbnormally =
         getLong(ATTR_REPLICATION_ASSURANCE_COMPLETED_ABNORMALLY);
    replicationAssuranceCompletedNormally =
         getLong(ATTR_REPLICATION_ASSURANCE_COMPLETED_NORMALLY);
    replicationAssuranceCompletedWithShutdown =
         getLong(ATTR_REPLICATION_ASSURANCE_COMPLETED_WITH_SHUTDOWN);
    replicationAssuranceCompletedWithTimeout =
         getLong(ATTR_REPLICATION_ASSURANCE_COMPLETED_WITH_TIMEOUT);
    replicationAssuranceSubmittedOperations =
         getLong(ATTR_REPLICATION_ASSURANCE_SUBMITTED_OPERATIONS);
    replicationBacklog = getLong(ATTR_REPLICATION_BACKLOG);
    requeueRetryAddFailedCount = getLong(ATTR_REQUEUE_RETRY_ADD_FAILED_COUNT);
    requeueRetryAddSuccessCount = getLong(ATTR_REQUEUE_RETRY_ADD_SUCCESS_COUNT);
    requeueRetryDeleteFailedCount =
         getLong(ATTR_REQUEUE_RETRY_DELETE_FAILED_COUNT);
    requeueRetryDeleteSuccessCount =
         getLong(ATTR_REQUEUE_RETRY_DELETE_SUCCESS_COUNT);
    requeueRetryModifyFailedCount =
         getLong(ATTR_REQUEUE_RETRY_MODIFY_FAILED_COUNT);
    requeueRetryModifySuccessCount =
         getLong(ATTR_REQUEUE_RETRY_MODIFY_SUCCESS_COUNT);
    requeueRetryModifyDNFailedCount =
         getLong(ATTR_REQUEUE_RETRY_MODIFY_DN_FAILED_COUNT);
    requeueRetryModifyDNSuccessCount =
         getLong(ATTR_REQUEUE_RETRY_MODIFY_DN_SUCCESS_COUNT);
    requeueRetryOpFailedCount = getLong(ATTR_REQUEUE_RETRY_OP_FAILED_COUNT);
    requeueRetryOpSuccessCount = getLong(ATTR_REQUEUE_RETRY_OP_SUCCESS_COUNT);
    requeueRetrySuccessTotalDurationMillis =
         getLong(ATTR_REQUEUE_RETRY_OP_SUCCESS_TOTAL_DURATION_MILLIS);
    sentAcks = getLong(ATTR_SENT_ACKS);
    sentUpdates = getLong(ATTR_SENT_UPDATES);
    successfullyReplayed = getLong(ATTR_SUCCESSFUL_REPLAYED);
    totalAverageLatencyMillis = getLong(ATTR_TOTAL_AVERAGE_LATENCY_MILLIS);
    totalMaximumLatencyMillis = getLong(ATTR_TOTAL_MAXIMUM_LATENCY_MILLIS);
    totalMinimumLatencyMillis = getLong(ATTR_TOTAL_MINIMUM_LATENCY_MILLIS);
    totalNegativeLatencyUpdateCount =
         getLong(ATTR_TOTAL_NEGATIVE_LATENCY_UPDATE_COUNT);
    totalReplayed = getLong(ATTR_TOTAL_REPLAYED);
    totalSumLatencyMillis =  getLong(ATTR_TOTAL_SUM_LATENCY_MILLIS);
    totalUpdateCount = getLong(ATTR_TOTAL_UPDATE_COUNT);
    unresolvedNamingConflicts = getLong(ATTR_UNRESOLVED_NAMING_CONFLICTS);
    baseDN = getString(ATTR_BASE_DN);
    generationID = getString(ATTR_GENERATION_ID);
    replicaID = getString(ATTR_REPLICA_ID);

    String addr = null;
    Long   port = null;
    final String connectedTo = getString(ATTR_CONNECTED_TO);
    if (connectedTo != null)
    {
      try
      {
        final int colonPos = connectedTo.indexOf(':');
        if (colonPos > 0)
        {
          addr = connectedTo.substring(0, colonPos);
          port = Long.parseLong(connectedTo.substring(colonPos+1));
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        addr = null;
        port = null;
      }
    }

    replicationServerAddress = addr;
    replicationServerPort    = port;
  }



  /**
   * Retrieves the base DN for this replica.
   *
   * @return  The base DN for this replica, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the replica ID for this replica.
   *
   * @return  The replica ID for this replica, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getReplicaID()
  {
    return replicaID;
  }



  /**
   * Retrieves the generation ID for this replica.
   *
   * @return  The generation ID for this replica, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getGenerationID()
  {
    return generationID;
  }



  /**
   * Retrieves the address of the replication server to which this replica is
   * connected.
   *
   * @return  The address of the replication server to which this replica is
   *          connected, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public String getReplicationServerAddress()
  {
    return replicationServerAddress;
  }



  /**
   * Retrieves the port number of the replication server to which this replica
   * is connected.
   *
   * @return  The port number of the replication server to which this replica is
   *          connected, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getReplicationServerPort()
  {
    return replicationServerPort;
  }



  /**
   * Indicates whether this replica uses SSL when communicating with the
   * replication server.
   *
   * @return  {@code Boolean.TRUE} if this replica uses SSL when communicating
   *          with the replication server, {@code Boolean.FALSE} if it does not
   *          use SSL, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Boolean useSSL()
  {
    return useSSL;
  }



  /**
   * Retrieves the number of times this replica has lost the connection to a
   * replication server.
   *
   * @return  The number of times this replica has lost the connection to a
   *          replication server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getLostConnections()
  {
    return lostConnections;
  }



  /**
   * Retrieves the total number of replicated operations processed since the
   * server started.
   *
   * @return  The total number of replicated operations processed since the
   *          server started, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getTotalUpdateCount()
  {
    return totalUpdateCount;
  }



  /**
   * Retrieves the number of updates that this replica has received from the
   * replication server.
   *
   * @return  The number of updates that this replica has received from the
   *          replication server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getReceivedUpdates()
  {
    return receivedUpdates;
  }



  /**
   * Retrieves the number of updates that this replica has sent to the
   * replication server.
   *
   * @return  The number of updates that this replica has sent to the
   *          replication server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getSentUpdates()
  {
    return sentUpdates;
  }



  /**
   * Retrieves the number of acknowledgements that this replica has received
   * from other servers.
   *
   * @return  The number of acknowledgements that this replica has received
   *          from other servers, or {@code null} if it was not included in the
   *          monitor entry.
     */
  @Nullable()
  public Long getReceivedAcks()
  {
    return receivedAcks;
  }



  /**
   * Retrieves the number of acknowledgements that this replica has sent to
   * other servers.
   *
   * @return  The number of acknowledgements that this replica has sent to
   *          other servers, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getSentAcks()
  {
    return sentAcks;
  }



  /**
   * Retrieves the number of updates that are currently in progress in the
   * Directory Server and have not yet been sent to the replication server.
   *
   * @return  The number of updates that are currently in progress in the
   *          Directory Server and have not yet been sent to the replication
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getPendingUpdates()
  {
    return pendingUpdates;
  }



  /**
   * Retrieves the total number of updates that have been replayed in this
   * replica.
   *
   * @return  The total number of updates that have been replayed in this
   *          replica, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getTotalUpdatesReplayed()
  {
    return totalReplayed;
  }



  /**
   * Retrieves the number of updates that have been successfully replayed in
   * this replica without conflicts.
   *
   * @return  The number of updates that have been successfully replayed in this
   *          replica without conflicts, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public Long getUpdatesSuccessfullyReplayed()
  {
    return successfullyReplayed;
  }



  /**
   * Retrieves the number of failures that have occurred while attempting to
   * replay changes.
   *
   * @return  The number of failures that have occurred while attempting to
   *          replay changes, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getUpdateReplayFailures()
  {
    return failedReplayed;
  }



  /**
   * Retrieves the number of updates that have been replayed in this replica
   * after automatically resolving a modify conflict.
   *
   * @return  The number of updates that have been replayed in this replica
   *          after automatically resolving a modify conflict, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getUpdatesReplayedAfterModifyConflict()
  {
    return replayedAfterModifyConflict;
  }



  /**
   * Retrieves the number of updates that have been replayed in this replica
   * after automatically resolving a naming conflict.
   *
   * @return  The number of updates that have been replayed in this replica
   *          after automatically resolving a naming conflict, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getUpdatesReplayedAfterNamingConflict()
  {
    return replayedAfterNamingConflict;
  }



  /**
   * Retrieves the number of updates that could not be replayed as a result of a
   * naming conflict that could not be automatically resolved.
   *
   * @return  The number of updates that could not be replayed as a result of a
   *          naming conflict that could not be automatically resolved, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getUnresolvedNamingConflicts()
  {
    return unresolvedNamingConflicts;
  }



  /**
   * Retrieves the number of conflict entries that currently exist in the
   * associated backend.
   *
   * @return  The number of conflict entries that currently exist in the
   *          associated backend, or {@code null} if it was not included in the
   *          monitor entry.
   *
   *
   * The name of the attribute that contains the number of conflict entries
   * that currently exist in the associated backend.
   */
  @Nullable()
  public Long getConflictEntryCount()
  {
    return conflictEntryCount;
  }



  /**
   * Retrieves the current receive window size for this replica.
   *
   * @return  The current receive window size for this replica, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getCurrentReceiveWindowSize()
  {
    return currentReceiveWindowSize;
  }



  /**
   * Retrieves the current send window size for this replica.
   *
   * @return  The current send window size for this replica, or {@code null} if
   *          it was not included in the monitor entry.
   */
  @Nullable()
  public Long getCurrentSendWindowSize()
  {
    return currentSendWindowSize;
  }



  /**
   * Retrieves the maximum receive window size for this replica.
   *
   * @return  The maximum receive window size for this replica, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getMaximumReceiveWindowSize()
  {
    return maxReceiveWindowSize;
  }



  /**
   * Retrieves the maximum send window size for this replica.
   *
   * @return  The maximum send window size for this replica, or {@code null} if
   *          it was not included in the monitor entry.
   */
  @Nullable()
  public Long getMaximumSendWindowSize()
  {
    return maxSendWindowSize;
  }



  /**
   * Retrieves the number of changes that have been applied in one or more other
   * replicas but have not yet been applied in the local server.
   *
   * @return  The number of changes that have been applied in one or more other
   *          replicas but have not yet been applied in the local server, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getReplicationBacklog()
  {
    return replicationBacklog;
  }



  /**
   * Retrieves the completion time for the oldest change that has been applied
   * in one or other replicas but has not yet been applied in the local server.
   *
   * @return  The completion time for the oldest change that has been applied in
   *          one or more other replicas but has not yet been applied in the
   *          local server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Date getOldestBacklogChangeTime()
  {
    return oldestBacklogChangeTime;
  }



  /**
   * Retrieves the number of changes in the pending changes queue that have not
   * yet been committed to the local database.
   *
   * @return  The number of changes in the pending changes queue that have not
   *          yet been committed to the local database, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getPendingChangesCurrentUncommittedSize()
  {
    return pendingChangesCurrentUncommittedSize;
  }



  /**
   * Retrieves the age, in milliseconds, of the oldest operation in the
   * pending changes queue.
   *
   * @return  The age, in milliseconds, of the oldest operation in the pending
   *          changes queue, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getAgeOfOldestPendingUpdateMillis()
  {
    return ageOfOldestPendingUpdateMillis;
  }



  /**
   * Retrieves the maximum number of operations that may be held in the
   * pending changes queue.
   *
   * @return  The maximum number of operations that may be held in the pending
   *          changes queue, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getPendingChangesMaxCapacity()
  {
    return pendingChangesMaxCapacity;
  }



  /**
   * Retrieves the largest number of operations that have been in the pending
   * changes queue at any time.
   *
   * @return  The largest number of operations that have been in the pending
   *          changes queue at any time, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public Long getPendingChangesLargestSizeReached()
  {
    return pendingChangesLargestSizeReached;
  }



  /**
   * Retrieves the number of times that the server attempted to add a change to
   * the pending changes queue when it was already full.
   *
   * @return  The number of times that the server attempted to add a change to
   *          the pending changes queue when it was already full, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getPendingChangesNumTimesAddedToFullQueue()
  {
    return pendingChangesNumTimesAddedToFullQueue;
  }



  /**
   * Retrieves the number of times that the server has logged that an operation
   * in the pending changes queue has stalled.
   *
   * @return  The number of times that the server has logged that an operation
   *          in the pending changes queue has stalled, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getPendingChangesNumTimesStallLogged()
  {
    return pendingChangesNumTimesStallLogged;
  }



  /**
   * Retrieves the latency, in milliseconds, of the last update that was
   * successfully replayed.
   *
   * @return  The latency, in milliseconds, of the last update that was
   *          successfully replayed, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public Long getLastUpdateLatencyMillis()
  {
    return lastUpdateLatencyMillis;
  }



  /**
   * Retrieves the average replication latency, in milliseconds, for operations
   * processed over a recent interval.
   *
   * @return  The average replication latency, in milliseconds, for operations
   *          processed over a recent interval, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Long getRecentAverageLatencyMillis()
  {
    return recentAverageLatencyMillis;
  }



  /**
   * Retrieves the maximum replication latency, in milliseconds, for any
   * operation processed over a recent interval.
   *
   * @return  The maximum replication latency, in milliseconds, for any
   *          operation processed over a recent interval, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getRecentMaximumLatencyMillis()
  {
    return recentMaximumLatencyMillis;
  }



  /**
   * Retrieves the minimum replication latency, in milliseconds, for any
   * operation processed over a recent interval.
   *
   * @return  The minimum replication latency, in milliseconds, for any
   *          operation processed over a recent interval, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getRecentMinimumLatencyMillis()
  {
    return recentMinimumLatencyMillis;
  }



  /**
   * Retrieves the number of negative replication latencies encountered over a
   * recent interval.
   *
   * @return  The number of negative replication latencies encountered over a
   *          recent interval, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getRecentNegativeLatencyUpdateCount()
  {
    return recentNegativeLatencyUpdateCount;
  }



  /**
   * Retrieves the sum of latencies, in milliseconds, for operations processed
   * over a recent interval.
   *
   * @return  The sum of latencies, in milliseconds, for operations processed
   *          over a recent interval, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public Long getRecentSumLatencyMillis()
  {
    return recentSumLatencyMillis;
  }



  /**
   * Retrieves the number of operations processed over the recent interval used
   * for recent replication latency calculations.
   *
   * @return  The number of operations processed over the recent interval, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getRecentUpdateCount()
  {
    return recentUpdateCount;
  }



  /**
   * Retrieves the average replication latency, in milliseconds, for operations
   * processed since the server was started.
   *
   * @return  The average replication latency, in milliseconds, for operations
   *          processed since the server was started, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public Long getTotalAverageLatencyMillis()
  {
    return totalAverageLatencyMillis;
  }



  /**
   * Retrieves the maximum replication latency, in milliseconds, for any
   * operation processed since the server was started.
   *
   * @return  The maximum replication latency, in milliseconds, for any
   *          operation processed since the server was started, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getTotalMaximumLatencyMillis()
  {
    return totalMaximumLatencyMillis;
  }



  /**
   * Retrieves the minimum replication latency, in milliseconds, for any
   * operation processed since the server was started.
   *
   * @return  The minimum replication latency, in milliseconds, for any
   *          operation processed since the server was started, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getTotalMinimumLatencyMillis()
  {
    return totalMinimumLatencyMillis;
  }



  /**
   * Retrieves the number of negative replication latencies encountered since
   * the server was started.
   *
   * @return  The number of negative replication latencies encountered since the
   *          server was started, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getTotalNegativeLatencyUpdateCount()
  {
    return totalNegativeLatencyUpdateCount;
  }



  /**
   * Retrieves the sum of latencies, in milliseconds, for operations processed
   * since the server was started.
   *
   * @return  The sum of latencies, in milliseconds, for operations processed
   *          since the server was started.
   */
  @Nullable()
  public Long getTotalSumLatencyMillis()
  {
    return totalSumLatencyMillis;
  }



  /**
   * Retrieves the number of changes that have begun processing with replication
   * assurance enabled.
   *
   * @return  The number of changes that have begun processing with replication
   *          assurance enabled, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getReplicationAssuranceSubmittedOperations()
  {
    return replicationAssuranceSubmittedOperations;
  }



  /**
   * Retrieves the number of changes that were processed with replication
   * assurance and completed successfully within the assurance constraints.
   *
   * @return  The number of changes that were processed with replication
   *          assurance and completed successfully within the assurance
   *          constraints, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getReplicationAssuranceCompletedNormally()
  {
    return replicationAssuranceCompletedNormally;
  }



  /**
   * Retrieves the number of changes that were processed with replication
   * assurance but could not be completed successfully within the assurance
   * constraints.
   *
   * @return  The number of changes that were processed with replication
   *          assurance but could not be completed successfully within the
   *          assurance constraints, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public Long getReplicationAssuranceCompletedAbnormally()
  {
    return replicationAssuranceCompletedAbnormally;
  }



  /**
   * Retrieves the number of changes that were processed with replication
   * assurance but could not be completed successfully within the assurance
   * constraints because a timeout was encountered.
   *
   * @return  The number of changes that were processed with replication
   *          assurance but could not be completed successfully within the
   *          assurance constraints because a timeout was encountered, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getReplicationAssuranceCompletedWithTimeout()
  {
    return replicationAssuranceCompletedWithTimeout;
  }



  /**
   * Retrieves the number of changes that were processed with replication
   * assurance but could not be completed successfully within the assurance
   * constraints because of a server shutdown.
   *
   * @return  The number of changes that were processed with replication
   *          assurance but could not be completed successfully within the
   *          assurance constraints because of a server shutdown, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getReplicationAssuranceCompletedWithShutdown()
  {
    return replicationAssuranceCompletedWithShutdown;
  }



  /**
   * Retrieves the number of operations of any type that failed on their initial
   * attempt, but that were requeued and succeeded on a retry.
   *
   * @return  The number of operations of any type that failed on their initial
   *          attempt, but that were requeued and succeeded on a retry, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequeueRetryOpSuccessCount()
  {
    return requeueRetryOpSuccessCount;
  }



  /**
   * Retrieves the number of operations of any type that failed on their initial
   * attempt, were requeued, and failed again on a retry.
   *
   * @return  The number of operations of any type that failed on their initial
   *          attempt, were requeued, and failed again on a retry, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequeueRetryOpFailedCount()
  {
    return requeueRetryOpFailedCount;
  }



  /**
   * Retrieves the number of add operations that failed on their initial
   * attempt, but that were requeued and succeeded on a retry.
   *
   * @return  The number of add operations that failed on their initial attempt,
   *          but that were requeued and succeeded on a retry, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequeueRetryAddSuccessCount()
  {
    return requeueRetryAddSuccessCount;
  }



  /**
   * Retrieves the number of add operations that failed on their initial
   * attempt, were requeued, and failed again on a retry.
   *
   * @return  The number of add operations that failed on their initial attempt,
   *          were requeued, and failed again on a retry, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequeueRetryAddFailedCount()
  {
    return requeueRetryAddFailedCount;
  }



  /**
   * Retrieves the number of delete operations that failed on their initial
   * attempt, but that were requeued and succeeded on a retry.
   *
   * @return  The number of delete operations that failed on their initial
   *          attempt, but that were requeued and succeeded on a retry, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequeueRetryDeleteSuccessCount()
  {
    return requeueRetryDeleteSuccessCount;
  }



  /**
   * Retrieves the number of delete operations that failed on their initial
   * attempt, were requeued, and failed again on a retry.
   *
   * @return  The number of delete operations that failed on their initial
   *          attempt, were requeued, and failed again on a retry, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequeueRetryDeleteFailedCount()
  {
    return requeueRetryDeleteFailedCount;
  }



  /**
   * Retrieves the number of modify operations that failed on their initial
   * attempt, but that were requeued and succeeded on a retry.
   *
   * @return  The number of modify operations that failed on their initial
   *          attempt, but that were requeued and succeeded on a retry, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequeueRetryModifySuccessCount()
  {
    return requeueRetryModifySuccessCount;
  }



  /**
   * Retrieves the number of modify operations that failed on their initial
   * attempt, were requeued, and failed again on a retry.
   *
   * @return  The number of modify operations that failed on their initial
   *          attempt, were requeued, and failed again on a retry, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequeueRetryModifyFailedCount()
  {
    return requeueRetryModifyFailedCount;
  }



  /**
   * Retrieves the number of modify DN operations that failed on their initial
   * attempt, but that were requeued and succeeded on a retry.
   *
   * @return  The number of modify DN operations that failed on their initial
   *          attempt, but that were requeued and succeeded on a retry, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequeueRetryModifyDNSuccessCount()
  {
    return requeueRetryModifyDNSuccessCount;
  }



  /**
   * Retrieves the number of modify DN operations that failed on their initial
   * attempt, were requeued, and failed again on a retry.
   *
   * @return  The number of modify DN operations that failed on their initial
   *          attempt, were requeued, and failed again on a retry, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequeueRetryModifyDNFailedCount()
  {
    return requeueRetryModifyDNFailedCount;
  }



  /**
   * Retrieves the average length of time, in milliseconds, required to
   * successfully process operations on a retry attempt after the initial
   * failure.
   *
   * @return  The average length of time, in milliseconds, required to
   *          successfully process operations on a retry attempt after the
   *          initial failure, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Double getRequeueRetrySuccessAverageDurationMillis()
  {
    return requeueRetrySuccessAverageDurationMillis;
  }



  /**
   * Retrieves the maximum length of time, in milliseconds, required to
   * successfully process an operation on a retry attempt after the initial
   * failure.
   *
   * @return  The maximum length of time, in milliseconds, required to
   *          successfully process an operation on a retry attempt after the
   *          initial failure, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Double getRequeueRetrySuccessMaximumDurationMillis()
  {
    return requeueRetrySuccessMaximumDurationMillis;
  }



  /**
   * Retrieves the total length of time, in milliseconds, required to process
   * operations that succeeded on a retry attempt after an initial failure.
   *
   * @return  The total length of time, in milliseconds, required to process
   *          operations that succeeded on a retry attempt after an initial
   *          failure, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getRequeueRetrySuccessTotalDurationMillis()
  {
    return requeueRetrySuccessTotalDurationMillis;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_REPLICA_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_REPLICA_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(30));

    if (baseDN != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BASE_DN,
           INFO_REPLICA_DISPNAME_BASE_DN.get(),
           INFO_REPLICA_DESC_BASE_DN.get(),
           baseDN);
    }

    if (replicaID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REPLICA_ID,
           INFO_REPLICA_DISPNAME_REPLICA_ID.get(),
           INFO_REPLICA_DESC_REPLICA_ID.get(),
           replicaID);
    }

    if (generationID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_GENERATION_ID,
           INFO_REPLICA_DISPNAME_GENERATION_ID.get(),
           INFO_REPLICA_DESC_GENERATION_ID.get(),
           generationID);
    }

    if (replicationServerAddress != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CONNECTED_TO,
           INFO_REPLICA_DISPNAME_CONNECTED_TO.get(),
           INFO_REPLICA_DESC_CONNECTED_TO.get(),
           replicationServerAddress + ':' + replicationServerPort);
    }

    if (useSSL != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SSL_ENCRYPTION,
           INFO_REPLICA_DISPNAME_USE_SSL.get(),
           INFO_REPLICA_DESC_USE_SSL.get(),
           useSSL);
    }

    if (lostConnections != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LOST_CONNECTIONS,
           INFO_REPLICA_DISPNAME_LOST_CONNECTIONS.get(),
           INFO_REPLICA_DESC_LOST_CONNECTIONS.get(),
           lostConnections);
    }

    if (totalUpdateCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_UPDATE_COUNT,
           INFO_REPLICA_DISPNAME_TOTAL_UPDATE_COUNT.get(),
           INFO_REPLICA_DESC_TOTAL_UPDATE_COUNT.get(),
           totalUpdateCount);
    }

    if (receivedUpdates != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECEIVED_UPDATES,
           INFO_REPLICA_DISPNAME_RECEIVED_UPDATES.get(),
           INFO_REPLICA_DESC_RECEIVED_UPDATES.get(),
           receivedUpdates);
    }

    if (sentUpdates != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SENT_UPDATES,
           INFO_REPLICA_DISPNAME_SENT_UPDATES.get(),
           INFO_REPLICA_DESC_SENT_UPDATES.get(),
           sentUpdates);
    }

    if (receivedAcks != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECEIVED_ACKS,
           INFO_REPLICA_DISPNAME_RECEIVED_ACKS.get(),
           INFO_REPLICA_DESC_RECEIVED_ACKS.get(),
           receivedAcks);
    }

    if (sentAcks != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SENT_ACKS,
           INFO_REPLICA_DISPNAME_SENT_ACKS.get(),
           INFO_REPLICA_DESC_SENT_ACKS.get(),
           sentAcks);
    }

    if (pendingUpdates != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PENDING_UPDATES,
           INFO_REPLICA_DISPNAME_PENDING_UPDATES.get(),
           INFO_REPLICA_DESC_PENDING_UPDATES.get(),
           pendingUpdates);
    }

    if (totalReplayed != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_REPLAYED,
           INFO_REPLICA_DISPNAME_TOTAL_REPLAYED.get(),
           INFO_REPLICA_DESC_TOTAL_REPLAYED.get(),
           totalReplayed);
    }

    if (successfullyReplayed != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SUCCESSFUL_REPLAYED,
           INFO_REPLICA_DISPNAME_SUCCESSFUL_REPLAYED.get(),
           INFO_REPLICA_DESC_SUCCESSFUL_REPLAYED.get(),
           successfullyReplayed);
    }

    if (failedReplayed != null)
    {
      addMonitorAttribute(attrs,
           ATTR_FAILED_REPLAYED,
           INFO_REPLICA_DISPNAME_FAILED_REPLAYED.get(),
           INFO_REPLICA_DESC_FAILED_REPLAYED.get(),
           failedReplayed);
    }

    if (replayedAfterModifyConflict != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RESOLVED_MODIFY_CONFLICTS,
           INFO_REPLICA_DISPNAME_RESOLVED_MODIFY_CONFLICTS.get(),
           INFO_REPLICA_DESC_RESOLVED_MODIFY_CONFLICTS.get(),
           replayedAfterModifyConflict);
    }

    if (replayedAfterNamingConflict != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RESOLVED_NAMING_CONFLICTS,
           INFO_REPLICA_DISPNAME_RESOLVED_NAMING_CONFLICTS.get(),
           INFO_REPLICA_DESC_RESOLVED_NAMING_CONFLICTS.get(),
           replayedAfterNamingConflict);
    }

    if (unresolvedNamingConflicts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_UNRESOLVED_NAMING_CONFLICTS,
           INFO_REPLICA_DISPNAME_UNRESOLVED_NAMING_CONFLICTS.get(),
           INFO_REPLICA_DESC_UNRESOLVED_NAMING_CONFLICTS.get(),
           unresolvedNamingConflicts);
    }

    if (conflictEntryCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CONFLICT_ENTRY_COUNT,
           INFO_REPLICA_DISPNAME_CONFLICT_ENTRY_COUNT.get(),
           INFO_REPLICA_DESC_CONFLICT_ENTRY_COUNT.get(),
           conflictEntryCount);
    }

    if (currentReceiveWindowSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_RECEIVE_WINDOW_SIZE,
           INFO_REPLICA_DISPNAME_CURRENT_RECEIVE_WINDOW_SIZE.get(),
           INFO_REPLICA_DESC_CURRENT_RECEIVE_WINDOW_SIZE.get(),
           currentReceiveWindowSize);
    }

    if (currentSendWindowSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_SEND_WINDOW_SIZE,
           INFO_REPLICA_DISPNAME_CURRENT_SEND_WINDOW_SIZE.get(),
           INFO_REPLICA_DESC_CURRENT_SEND_WINDOW_SIZE.get(),
           currentSendWindowSize);
    }

    if (maxReceiveWindowSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_RECEIVE_WINDOW_SIZE,
           INFO_REPLICA_DISPNAME_MAX_RECEIVE_WINDOW_SIZE.get(),
           INFO_REPLICA_DESC_MAX_RECEIVE_WINDOW_SIZE.get(),
           maxReceiveWindowSize);
    }

    if (maxSendWindowSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_SEND_WINDOW_SIZE,
           INFO_REPLICA_DISPNAME_MAX_SEND_WINDOW_SIZE.get(),
           INFO_REPLICA_DESC_MAX_SEND_WINDOW_SIZE.get(),
           maxSendWindowSize);
    }

    if (replicationBacklog != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REPLICATION_BACKLOG,
           INFO_REPLICA_DISPNAME_REPLICATION_BACKLOG.get(),
           INFO_REPLICA_DESC_REPLICATION_BACKLOG.get(),
           replicationBacklog);
    }

    if (oldestBacklogChangeTime != null)
    {
      addMonitorAttribute(attrs,
           ATTR_OLDEST_BACKLOG_CHANGE_TIME,
           INFO_REPLICA_DISPNAME_OLDEST_BACKLOG_CHANGE_TIME.get(),
           INFO_REPLICA_DESC_OLDEST_BACKLOG_CHANGE_TIME.get(),
           oldestBacklogChangeTime);
    }

    if (pendingChangesCurrentUncommittedSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PENDING_CHANGES_CURRENT_UNCOMMITTED_SIZE,
           INFO_REPLICA_DISPNAME_PENDING_CHANGES_UNCOMMITTED_SIZE.get(),
           INFO_REPLICA_DESC_PENDING_CHANGES_UNCOMMITTED_SIZE.get(),
           pendingChangesCurrentUncommittedSize);
    }

    if (ageOfOldestPendingUpdateMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_AGE_OF_OLDEST_PENDING_UPDATE_MILLIS,
           INFO_REPLICA_DISPNAME_AGE_OF_OLDEST_PENDING_UPDATE.get(),
           INFO_REPLICA_DESC_AGE_OF_OLDEST_PENDING_UPDATE.get(),
           ageOfOldestPendingUpdateMillis);
    }

    if (pendingChangesMaxCapacity != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PENDING_CHANGES_MAX_CAPACITY,
           INFO_REPLICA_DISPNAME_PENDING_CHANGES_MAX_CAPACITY.get(),
           INFO_REPLICA_DESC_PENDING_CHANGES_MAX_CAPACITY.get(),
           pendingChangesMaxCapacity);
    }

    if (pendingChangesLargestSizeReached != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PENDING_CHANGES_LARGEST_SIZE_REACHED,
           INFO_REPLICA_DISPNAME_PENDING_CHANGES_LARGEST_SIZE.get(),
           INFO_REPLICA_DESC_PENDING_CHANGES_LARGEST_SIZE.get(),
           pendingChangesLargestSizeReached);
    }

    if (pendingChangesNumTimesAddedToFullQueue != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PENDING_CHANGES_NUM_TIMES_ADDED_TO_FULL_QUEUE,
           INFO_REPLICA_DISPNAME_PENDING_CHANGES_ADD_TO_FULL.get(),
           INFO_REPLICA_DESC_PENDING_CHANGES_ADD_TO_FULL.get(),
           pendingChangesNumTimesAddedToFullQueue);
    }

    if (pendingChangesNumTimesStallLogged != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PENDING_CHANGES_NUM_TIMES_STALL_LOGGED,
           INFO_REPLICA_DISPNAME_PENDING_CHANGES_STALL_LOGGED.get(),
           INFO_REPLICA_DESC_PENDING_CHANGES_STALL_LOGGED.get(),
           pendingChangesNumTimesStallLogged);
    }

    if (lastUpdateLatencyMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LAST_UPDATE_LATENCY_MILLIS,
           INFO_REPLICA_DISPNAME_LAST_UPDATE_LATENCY.get(),
           INFO_REPLICA_DESC_LAST_UPDATE_LATENCY.get(),
           lastUpdateLatencyMillis);
    }

    if (recentAverageLatencyMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_AVERAGE_LATENCY_MILLIS,
           INFO_REPLICA_DISPNAME_RECENT_AVERAGE_LATENCY.get(),
           INFO_REPLICA_DESC_RECENT_AVERAGE_LATENCY.get(),
           recentAverageLatencyMillis);
    }

    if (recentMaximumLatencyMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_MAXIMUM_LATENCY_MILLIS,
           INFO_REPLICA_DISPNAME_RECENT_MAX_LATENCY.get(),
           INFO_REPLICA_DESC_RECENT_MAX_LATENCY.get(),
           recentMaximumLatencyMillis);
    }

    if (recentMinimumLatencyMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_MINIMUM_LATENCY_MILLIS,
           INFO_REPLICA_DISPNAME_RECENT_MIN_LATENCY.get(),
           INFO_REPLICA_DESC_RECENT_MIN_LATENCY.get(),
           recentMinimumLatencyMillis);
    }

    if (recentNegativeLatencyUpdateCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_NEGATIVE_LATENCY_UPDATE_COUNT,
           INFO_REPLICA_DISPNAME_RECENT_NEGATIVE_LATENCY.get(),
           INFO_REPLICA_DESC_RECENT_NEGATIVE_LATENCY.get(),
           recentNegativeLatencyUpdateCount);
    }

    if (recentSumLatencyMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_SUM_LATENCY_MILLIS,
           INFO_REPLICA_DISPNAME_RECENT_SUM_LATENCY.get(),
           INFO_REPLICA_DESC_RECENT_SUM_LATENCY.get(),
           recentSumLatencyMillis);
    }

    if (recentUpdateCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_UPDATE_COUNT,
           INFO_REPLICA_DISPNAME_RECENT_UPDATE_COUNT.get(),
           INFO_REPLICA_DESC_RECENT_UPDATE_COUNT.get(),
           recentUpdateCount);
    }

    if (totalAverageLatencyMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_AVERAGE_LATENCY_MILLIS,
           INFO_REPLICA_DISPNAME_TOTAL_AVERAGE_LATENCY.get(),
           INFO_REPLICA_DESC_TOTAL_AVERAGE_LATENCY.get(),
           totalAverageLatencyMillis);
    }

    if (totalMaximumLatencyMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_MAXIMUM_LATENCY_MILLIS,
           INFO_REPLICA_DISPNAME_TOTAL_MAX_LATENCY.get(),
           INFO_REPLICA_DESC_TOTAL_MAX_LATENCY.get(),
           totalMaximumLatencyMillis);
    }

    if (totalMinimumLatencyMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_MINIMUM_LATENCY_MILLIS,
           INFO_REPLICA_DISPNAME_TOTAL_MIN_LATENCY.get(),
           INFO_REPLICA_DESC_TOTAL_MIN_LATENCY.get(),
           totalMinimumLatencyMillis);
    }

    if (totalNegativeLatencyUpdateCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_NEGATIVE_LATENCY_UPDATE_COUNT,
           INFO_REPLICA_DISPNAME_TOTAL_NEGATIVE_LATENCY.get(),
           INFO_REPLICA_DESC_TOTAL_NEGATIVE_LATENCY.get(),
           totalNegativeLatencyUpdateCount);
    }

    if (totalSumLatencyMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_SUM_LATENCY_MILLIS,
           INFO_REPLICA_DISPNAME_TOTAL_SUM_LATENCY.get(),
           INFO_REPLICA_DESC_TOTAL_SUM_LATENCY.get(),
           totalSumLatencyMillis);
    }

    if (replicationAssuranceSubmittedOperations != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REPLICATION_ASSURANCE_SUBMITTED_OPERATIONS,
           INFO_REPLICA_DISPNAME_REPL_ASSURANCE_SUBMITTED_OPS.get(),
           INFO_REPLICA_DESC_REPL_ASSURANCE_SUBMITTED_OPS.get(),
           replicationAssuranceSubmittedOperations);
    }

    if (replicationAssuranceCompletedNormally != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REPLICATION_ASSURANCE_COMPLETED_NORMALLY,
           INFO_REPLICA_DISPNAME_REPL_ASSURANCE_COMPLETED_NORMALLY.get(),
           INFO_REPLICA_DESC_REPL_ASSURANCE_COMPLETED_NORMALLY.get(),
           replicationAssuranceCompletedNormally);
    }

    if (replicationAssuranceCompletedAbnormally != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REPLICATION_ASSURANCE_COMPLETED_ABNORMALLY,
           INFO_REPLICA_DISPNAME_REPL_ASSURANCE_COMPLETED_ABNORMALLY.get(),
           INFO_REPLICA_DESC_REPL_ASSURANCE_COMPLETED_ABNORMALLY.get(),
           replicationAssuranceCompletedAbnormally);
    }

    if (replicationAssuranceCompletedWithTimeout != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REPLICATION_ASSURANCE_COMPLETED_WITH_TIMEOUT,
           INFO_REPLICA_DISPNAME_REPL_ASSURANCE_COMPLETED_WITH_TIMEOUT.get(),
           INFO_REPLICA_DESC_REPL_ASSURANCE_COMPLETED_WITH_TIMEOUT.get(),
           replicationAssuranceCompletedWithTimeout);
    }

    if (replicationAssuranceCompletedWithShutdown != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REPLICATION_ASSURANCE_COMPLETED_WITH_SHUTDOWN,
           INFO_REPLICA_DISPNAME_REPL_ASSURANCE_COMPLETED_WITH_SHUTDOWN.get(),
           INFO_REPLICA_DESC_REPL_ASSURANCE_COMPLETED_WITH_SHUTDOWN.get(),
           replicationAssuranceCompletedWithShutdown);
    }

    if (requeueRetryOpSuccessCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_OP_SUCCESS_COUNT,
           INFO_REPLICA_DISPNAME_RETRY_OP_SUCCESS_COUNT.get(),
           INFO_REPLICA_DESC_RETRY_OP_SUCCESS_COUNT.get(),
           requeueRetryOpSuccessCount);
    }

    if (requeueRetryOpFailedCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_OP_FAILED_COUNT,
           INFO_REPLICA_DISPNAME_RETRY_OP_FAILED_COUNT.get(),
           INFO_REPLICA_DESC_RETRY_OP_FAILED_COUNT.get(),
           requeueRetryOpFailedCount);
    }

    if (requeueRetryAddSuccessCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_ADD_SUCCESS_COUNT,
           INFO_REPLICA_DISPNAME_RETRY_ADD_SUCCESS_COUNT.get(),
           INFO_REPLICA_DESC_RETRY_ADD_SUCCESS_COUNT.get(),
           requeueRetryAddSuccessCount);
    }

    if (requeueRetryAddFailedCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_ADD_FAILED_COUNT,
           INFO_REPLICA_DISPNAME_RETRY_ADD_FAILED_COUNT.get(),
           INFO_REPLICA_DESC_RETRY_ADD_FAILED_COUNT.get(),
           requeueRetryAddFailedCount);
    }

    if (requeueRetryDeleteSuccessCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_DELETE_SUCCESS_COUNT,
           INFO_REPLICA_DISPNAME_RETRY_DELETE_SUCCESS_COUNT.get(),
           INFO_REPLICA_DESC_RETRY_DELETE_SUCCESS_COUNT.get(),
           requeueRetryDeleteSuccessCount);
    }

    if (requeueRetryDeleteFailedCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_DELETE_FAILED_COUNT,
           INFO_REPLICA_DISPNAME_RETRY_DELETE_FAILED_COUNT.get(),
           INFO_REPLICA_DESC_RETRY_DELETE_FAILED_COUNT.get(),
           requeueRetryDeleteFailedCount);
    }

    if (requeueRetryModifySuccessCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_MODIFY_SUCCESS_COUNT,
           INFO_REPLICA_DISPNAME_RETRY_MODIFY_SUCCESS_COUNT.get(),
           INFO_REPLICA_DESC_RETRY_MODIFY_SUCCESS_COUNT.get(),
           requeueRetryModifySuccessCount);
    }

    if (requeueRetryModifyFailedCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_MODIFY_FAILED_COUNT,
           INFO_REPLICA_DISPNAME_RETRY_MODIFY_FAILED_COUNT.get(),
           INFO_REPLICA_DESC_RETRY_MODIFY_FAILED_COUNT.get(),
           requeueRetryModifyFailedCount);
    }

    if (requeueRetryModifyDNSuccessCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_MODIFY_DN_SUCCESS_COUNT,
           INFO_REPLICA_DISPNAME_RETRY_MODIFY_DN_SUCCESS_COUNT.get(),
           INFO_REPLICA_DESC_RETRY_MODIFY_DN_SUCCESS_COUNT.get(),
           requeueRetryModifyDNSuccessCount);
    }

    if (requeueRetryModifyDNFailedCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_MODIFY_DN_FAILED_COUNT,
           INFO_REPLICA_DISPNAME_RETRY_MODIFY_DN_FAILED_COUNT.get(),
           INFO_REPLICA_DESC_RETRY_MODIFY_DN_FAILED_COUNT.get(),
           requeueRetryModifyDNFailedCount);
    }

    if (requeueRetrySuccessAverageDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_OP_SUCCESS_AVERAGE_DURATION_MILLIS,
           INFO_REPLICA_DISPNAME_RETRY_AVERAGE_DURATION.get(),
           INFO_REPLICA_DESC_RETRY_AVERAGE_DURATION.get(),
           requeueRetrySuccessAverageDurationMillis);
    }

    if (requeueRetrySuccessMaximumDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_OP_SUCCESS_MAXIMUM_DURATION_MILLIS,
           INFO_REPLICA_DISPNAME_RETRY_MAX_DURATION.get(),
           INFO_REPLICA_DESC_RETRY_MAX_DURATION.get(),
           requeueRetrySuccessMaximumDurationMillis);
    }

    if (requeueRetrySuccessTotalDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUEUE_RETRY_OP_SUCCESS_TOTAL_DURATION_MILLIS,
           INFO_REPLICA_DISPNAME_RETRY_TOTAL_DURATION.get(),
           INFO_REPLICA_DESC_RETRY_TOTAL_DURATION.get(),
           requeueRetrySuccessTotalDurationMillis);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
