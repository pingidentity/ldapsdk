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



import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides basic information about the
 * Berkeley DB Java Edition environment in use for a backend.
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
 * The information that is provided includes:
 * <UL>
 *   <LI>The backend ID for the associated backend.</LI>
 *   <LI>The version string for the Berkeley DB Java Edition library.</LI>
 *   <LI>The path to the directory containing the database environment
 *       files.</LI>
 *   <LI>The amount of space consumed by the database files.</LI>
 *   <LI>The amount of memory currently consumed by the database cache.</LI>
 *   <LI>The maximum amount of memory that may be consumed by the database
 *       cache.</LI>
 *   <LI>The percent of the total memory allowed for the database cache that is
 *       currently in use.</LI>
 *   <LI>Whether a checkpoint is currently in progress.</LI>
 *   <LI>The total number of checkpoints that have been completed.</LI>
 *   <LI>The time that the last completed checkpoint began.</LI>
 *   <LI>The time that the last completed checkpoint ended.</LI>
 *   <LI>The total duration of all checkpoints completed.</LI>
 *   <LI>The average duration of all checkpoints completed.</LI>
 *   <LI>The duration of the last checkpoint completed.</LI>
 *   <LI>The length of time since the last checkpoint.</LI>
 *   <LI>The number of log files that the cleaner needs to examine.</LI>
 *   <LI>The number of nodes evicted from the database cache.</LI>
 *   <LI>The number of random-access disk reads performed.</LI>
 *   <LI>The number of random-access disk writes performed.</LI>
 *   <LI>The number of sequential disk reads performed.</LI>
 *   <LI>The number of sequential disk writes performed.</LI>
 *   <LI>The number of active transactions in the database environment.</LI>
 *   <LI>The number of read locks held in the database environment.</LI>
 *   <LI>The number of write locks held in the database environment.</LI>
 *   <LI>The number of transactions waiting on locks.</LI>
 *   <LI>A set of generic statistics about the database environment.</LI>
 *   <LI>A set of generic statistics about the lock subsystem for the database
 *       environment.</LI>
 *   <LI>A set of generic statistics about the transaction subsystem for the
 *       database environment.</LI>
 * </UL>
 * The JE environment monitor entries provided by the server can be
 * retrieved using the {@link MonitorManager#getJEEnvironmentMonitorEntries}
 * method.  These entries provide specific methods for accessing information
 * about the JE environment (e.g., the
 * {@link JEEnvironmentMonitorEntry#getJEVersion} method can be used to retrieve
 * the Berkeley DB JE version).  Alternately, this information may be accessed
 * using the generic API.  See the {@link MonitorManager} class documentation
 * for an example that demonstrates the use of the generic API for accessing
 * monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JEEnvironmentMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in JE environment monitor entries.
   */
  @NotNull static final String JE_ENVIRONMENT_MONITOR_OC =
       "ds-je-environment-monitor-entry";



  /**
   * The name of the attribute that contains the number of active transactions.
   */
  @NotNull private static final String ATTR_ACTIVE_TXNS =
       "active-transaction-count";



  /**
   * The name of the attribute that contains the average duration of the all
   * checkpoints in milliseconds.
   */
  @NotNull private static final String ATTR_AVERAGE_CHECKPOINT_DURATION_MILLIS =
       "average-checkpoint-duration-millis";



  /**
   * The name of the attribute that contains the backend ID for the associated
   * backend.
   */
  @NotNull private static final String ATTR_BACKEND_ID = "backend-id";



  /**
   * The name of the attribute that contains the DB cache percent full.
   */
  @NotNull private static final String ATTR_CACHE_PCT_FULL =
       "db-cache-percent-full";



  /**
   * The name of the attribute that indicates whether a checkpoint is currently
   * in progress.
   */
  @NotNull private static final String ATTR_CHECKPOINT_IN_PROGRESS =
       "checkpoint-in-progress";



  /**
   * The name of the attribute that contains the cleaner backlog.
   */
  @NotNull private static final String ATTR_CLEANER_BACKLOG = "cleaner-backlog";



  /**
   * The name of the attribute that contains the current DB cache size.
   */
  @NotNull private static final String ATTR_CURRENT_CACHE_SIZE =
       "current-db-cache-size";



  /**
   * The name of the attribute that contains the path to the DB directory.
   */
  @NotNull private static final String ATTR_DB_DIRECTORY = "db-directory";



  /**
   * The name of the attribute that contains the DB on-disk size.
   */
  @NotNull private static final String ATTR_DB_ON_DISK_SIZE = "db-on-disk-size";



  /**
   * The name of the attribute that contains the Berkeley DB JE version string.
   */
  @NotNull private static final String ATTR_JE_VERSION = "je-version";



  /**
   * The name of the attribute that contains the duration of the last checkpoint
   * in milliseconds.
   */
  @NotNull private static final String ATTR_LAST_CHECKPOINT_DURATION_MILLIS =
       "last-checkpoint-duration-millis";



  /**
   * The name of the attribute that contains the time the last checkpoint began.
   */
  @NotNull private static final String ATTR_LAST_CHECKPOINT_START_TIME =
       "last-checkpoint-start-time";



  /**
   * The name of the attribute that contains the time the last checkpoint ended.
   */
  @NotNull private static final String ATTR_LAST_CHECKPOINT_STOP_TIME =
       "last-checkpoint-stop-time";



  /**
   * The name of the attribute that contains the time of the last checkpoint.
   *
   * @deprecated  Use {@link #ATTR_LAST_CHECKPOINT_STOP_TIME} instead.
   */
  @Deprecated()
  @NotNull private static final String ATTR_LAST_CHECKPOINT_TIME =
       "last-checkpoint-time";



  /**
   * The name of the attribute that contains the maximum cache size.
   */
  @NotNull private static final String ATTR_MAX_CACHE_SIZE =
       "max-db-cache-size";



  /**
   * The name of the attribute that contains the length of time in milliseconds
   * since the last checkpoint.
   */
  @NotNull private static final String ATTR_MILLIS_SINCE_LAST_CHECKPOINT =
       "millis-since-last-checkpoint";



  /**
   * The name of the attribute that contains the number of nodes evicted from
   * the cache.
   */
  @NotNull private static final String ATTR_NODES_EVICTED = "nodes-evicted";



  /**
   * The name of the attribute that contains the number of checkpoints
   * processed.
   */
  @NotNull private static final String ATTR_NUM_CHECKPOINTS = "num-checkpoints";



  /**
   * The name of the attribute that contains the number of read locks held.
   */
  @NotNull private static final String ATTR_NUM_READ_LOCKS = "read-locks-held";



  /**
   * The name of the attribute that contains the total duration of the all
   * checkpoints in milliseconds.
   */
  @NotNull private static final String ATTR_TOTAL_CHECKPOINT_DURATION_MILLIS =
       "total-checkpoint-duration-millis";



  /**
   * The name of the attribute that contains the number of transactions waiting
   * on locks.
   */
  @NotNull private static final String ATTR_NUM_WAITING_TXNS =
       "transactions-waiting-on-locks";



  /**
   * The name of the attribute that contains the number of write locks held.
   */
  @NotNull private static final String ATTR_NUM_WRITE_LOCKS =
       "write-locks-held";



  /**
   * The name of the attribute that contains the number of random reads.
   */
  @NotNull private static final String ATTR_RANDOM_READS = "random-read-count";



  /**
   * The name of the attribute that contains the number of random writes.
   */
  @NotNull private static final String ATTR_RANDOM_WRITES =
       "random-write-count";



  /**
   * The name of the attribute that contains the number of sequential reads.
   */
  @NotNull private static final String ATTR_SEQUENTIAL_READS =
       "sequential-read-count";



  /**
   * The name of the attribute that contains the number of sequential writes.
   */
  @NotNull private static final String ATTR_SEQUENTIAL_WRITES =
       "sequential-write-count";



  /**
   * The prefix that will be used for attribute names that contain generic
   * environment statistics.
   */
  @NotNull private static final String ATTR_PREFIX_ENV_STAT = "je-env-stat-";



  /**
   * The prefix that will be used for attribute names that contain generic lock
   * statistics.
   */
  @NotNull private static final String ATTR_PREFIX_LOCK_STAT = "je-lock-stat-";



  /**
   * The prefix that will be used for attribute names that contain generic
   * transaction statistics.
   */
  @NotNull private static final String ATTR_PREFIX_TXN_STAT = "je-txn-stat-";



  /**
   * The name that will be used for the property that contains generic
   * environment statistics.
   */
  @NotNull private static final String PROPERTY_ENV_STATS = "je-env-stats";



  /**
   * The name that will be used for the property that contains generic lock
   * statistics.
   */
  @NotNull private static final String PROPERTY_LOCK_STATS = "je-lock-stats";



  /**
   * The name that will be used for the property that contains generic
   * transaction statistics.
   */
  @NotNull private static final String PROPERTY_TXN_STATS = "je-txn-stats";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2557783119454069632L;



  // Indicates whether a checkpoint is currently in progress.
  @Nullable private final Boolean checkpointInProgress;

  // The time the last checkpoint began.
  @Nullable private final Date lastCheckpointStartTime;

  // The time the last checkpoint ended.
  @Nullable private final Date lastCheckpointStopTime;

  /**
   * The time the last checkpoint ended.
   *
   * @deprecated  Use lastCheckpointStopTime instead.
   */
  @Deprecated
  @Nullable private final Date lastCheckpointTime;

  // The number of active transactions.
  @Nullable private final Long activeTransactionCount;

  // The average duration for all checkpoints.
  @Nullable private final Long averageCheckpointDurationMillis;

  // The current cleaner backlog.
  @Nullable private final Long cleanerBacklog;

  // The current DB cache size.
  @Nullable private final Long currentDBCacheSize;

  // The current DB cache percent full.
  @Nullable private final Long dbCachePercentFull;

  // The current DB on-disk size.
  @Nullable private final Long dbOnDiskSize;

  // The duration for the last checkpoint.
  @Nullable private final Long lastCheckpointDurationMillis;

  // The maximum allowed DB cache size.
  @Nullable private final Long maxDBCacheSize;

  // The length of time since the last checkpoint.
  @Nullable private final Long millisSinceLastCheckpoint;

  // The number of nodes evicted from the DB cache.
  @Nullable private final Long nodesEvicted;

  // The number of checkpoints completed.
  @Nullable private final Long numCheckpoints;

  // The number of random reads performed.
  @Nullable private final Long randomReads;

  // The number of random writes performed.
  @Nullable private final Long randomWrites;

  // The number of read locks held.
  @Nullable private final Long readLocksHeld;

  // The number of sequential reads performed.
  @Nullable private final Long sequentialReads;

  // The number of sequential writes performed.
  @Nullable private final Long sequentialWrites;

  // The total duration for all checkpoints.
  @Nullable private final Long totalCheckpointDurationMillis;

  // The number of transactions waiting on locks.
  @Nullable private final Long transactionsWaitingOnLocks;

  // The number of write locks held.
  @Nullable private final Long writeLocksHeld;

  // The set of generic environment statistics.
  @NotNull private final Map<String,String> envStats;

  // The set of generic lock statistics.
  @NotNull private final Map<String,String> lockStats;

  // The set of generic transaction statistics.
  @NotNull private final Map<String,String> txnStats;

  // The backend ID for the associated backend.
  @Nullable private final String backendID;

  // The path to the directory containing the database files.
  @Nullable private final String dbDirectory;

  // The Berkeley DB JE version string.
  @Nullable private final String jeVersion;



  /**
   * Creates a new JE environment monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a JE environment monitor entry.
   *                It must not be {@code null}.
   */
  @SuppressWarnings("deprecation")
  public JEEnvironmentMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    activeTransactionCount     = getLong(ATTR_ACTIVE_TXNS);
    cleanerBacklog             = getLong(ATTR_CLEANER_BACKLOG);
    currentDBCacheSize         = getLong(ATTR_CURRENT_CACHE_SIZE);
    dbCachePercentFull         = getLong(ATTR_CACHE_PCT_FULL);
    dbOnDiskSize               = getLong(ATTR_DB_ON_DISK_SIZE);
    maxDBCacheSize             = getLong(ATTR_MAX_CACHE_SIZE);
    nodesEvicted               = getLong(ATTR_NODES_EVICTED);
    randomReads                = getLong(ATTR_RANDOM_READS);
    randomWrites               = getLong(ATTR_RANDOM_WRITES);
    readLocksHeld              = getLong(ATTR_NUM_READ_LOCKS);
    sequentialReads            = getLong(ATTR_SEQUENTIAL_READS);
    sequentialWrites           = getLong(ATTR_SEQUENTIAL_WRITES);
    transactionsWaitingOnLocks = getLong(ATTR_NUM_WAITING_TXNS);
    writeLocksHeld             = getLong(ATTR_NUM_WRITE_LOCKS);
    backendID                  = getString(ATTR_BACKEND_ID);
    dbDirectory                = getString(ATTR_DB_DIRECTORY);
    jeVersion                  = getString(ATTR_JE_VERSION);

    checkpointInProgress = getBoolean(ATTR_CHECKPOINT_IN_PROGRESS);
    lastCheckpointStartTime = getDate(ATTR_LAST_CHECKPOINT_START_TIME);
    lastCheckpointStopTime = getDate(ATTR_LAST_CHECKPOINT_STOP_TIME);
    lastCheckpointTime = getDate(ATTR_LAST_CHECKPOINT_TIME);
    averageCheckpointDurationMillis  =
         getLong(ATTR_AVERAGE_CHECKPOINT_DURATION_MILLIS);
    lastCheckpointDurationMillis =
         getLong(ATTR_LAST_CHECKPOINT_DURATION_MILLIS);
    millisSinceLastCheckpoint = getLong(ATTR_MILLIS_SINCE_LAST_CHECKPOINT);
    numCheckpoints = getLong(ATTR_NUM_CHECKPOINTS);
    totalCheckpointDurationMillis =
         getLong(ATTR_TOTAL_CHECKPOINT_DURATION_MILLIS);

    final LinkedHashMap<String,String> tmpEnvStats =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));
    final LinkedHashMap<String,String> tmpLockStats =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));
    final LinkedHashMap<String,String> tmpTxnStats =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));
    for (final Attribute a : entry.getAttributes())
    {
      final String name = StaticUtils.toLowerCase(a.getName());
      if (name.startsWith(ATTR_PREFIX_ENV_STAT))
      {
        tmpEnvStats.put(
             StaticUtils.toLowerCase(name.substring(
                  ATTR_PREFIX_ENV_STAT.length())),
             a.getValue());
      }
      else if (name.startsWith(ATTR_PREFIX_LOCK_STAT))
      {
        tmpLockStats.put(
             StaticUtils.toLowerCase(name.substring(
                  ATTR_PREFIX_LOCK_STAT.length())),
             a.getValue());
      }
      else if (name.startsWith(ATTR_PREFIX_TXN_STAT))
      {
        tmpTxnStats.put(
             StaticUtils.toLowerCase(name.substring(
                  ATTR_PREFIX_TXN_STAT.length())),
             a.getValue());
      }
    }

    envStats  = Collections.unmodifiableMap(tmpEnvStats);
    lockStats = Collections.unmodifiableMap(tmpLockStats);
    txnStats  = Collections.unmodifiableMap(tmpTxnStats);
  }



  /**
   * Retrieves the backend ID for the backend with which the Berkeley DB JE
   * database is associated.
   *
   * @return  The backend ID for the backend with which the Berkeley DB JE
   *          database is associated.
   */
  @Nullable()
  public String getBackendID()
  {
    return backendID;
  }



  /**
   * Retrieves the Berkeley DB JE version string for the database environment
   * of the associated backend.
   *
   * @return  The Berkeley DB JE version string for the database environment of
   *          the associated backend, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public String getJEVersion()
  {
    return jeVersion;
  }



  /**
   * Retrieves the path to the directory containing the database files.
   *
   * @return  The path to the directory containing the database files, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getDBDirectory()
  {
    return dbDirectory;
  }



  /**
   * Retrieves the amount of disk space in bytes consumed by the database files.
   *
   * @return  The amount of disk space in bytes consumed by the database files,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getDBOnDiskSize()
  {
    return dbOnDiskSize;
  }



  /**
   * Retrieves the amount of memory in bytes currently consumed by the database
   * cache.
   *
   * @return  The amount of memory in bytes currently consumed by the database
   *          cache, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getCurrentDBCacheSize()
  {
    return currentDBCacheSize;
  }



  /**
   * Retrieves the maximum amount of memory in bytes that may be consumed by the
   * database cache.
   *
   * @return  The maximum of memory in bytes that may be consumed by the
   *          database cache, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getMaxDBCacheSize()
  {
    return maxDBCacheSize;
  }



  /**
   * Retrieves the percentage of the maximum database cache size that is
   * currently in use.
   *
   * @return  The percentage of the maximum database cache size that is
   *          currently in use, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getDBCachePercentFull()
  {
    return dbCachePercentFull;
  }



  /**
   * Indicates whether a checkpoint is currently in progress in the associated
   * backend.
   *
   * @return  A {@code Boolean} value indicating whether a checkpoint is
   *          currently in progress in the associated backend, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Boolean checkpointInProgress()
  {
    return checkpointInProgress;
  }



  /**
   * Retrieves the number of checkpoints completed in the associated backend.
   *
   * @return  The number of checkpoints completed in the associated backend, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getNumCheckpoints()
  {
    return numCheckpoints;
  }



  /**
   * Retrieves the total duration in milliseconds of all checkpoints completed
   * in the associated backend.
   *
   * @return  The total duration in milliseconds of all checkpoints completed in
   *          the associated backend, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public Long getTotalCheckpointDurationMillis()
  {
    return totalCheckpointDurationMillis;
  }



  /**
   * Retrieves the average duration in milliseconds of all checkpoints completed
   * in the associated backend.
   *
   * @return  The average duration in milliseconds of all checkpoints completed
   *          in the associated backend, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public Long getAverageCheckpointDurationMillis()
  {
    return averageCheckpointDurationMillis;
  }



  /**
   * Retrieves the duration in milliseconds of the last checkpoint completed in
   * the associated backend.
   *
   * @return  The duration in milliseconds of the last checkpoint completed in
   *          the associated backend, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public Long getLastCheckpointDurationMillis()
  {
    return lastCheckpointDurationMillis;
  }



  /**
   * Retrieves the time that the last completed checkpoint began.
   *
   * @return  The time that the last completed checkpoint began, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Date getLastCheckpointStartTime()
  {
    return lastCheckpointStartTime;
  }



  /**
   * Retrieves the time that the last completed checkpoint ended.
   *
   * @return  The time that the last completed checkpoint ended, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Date getLastCheckpointStopTime()
  {
    return lastCheckpointStopTime;
  }



  /**
   * Retrieves the time that the last checkpoint occurred.
   *
   * @return  The time that the last checkpoint occurred, or {@code null} if it
   *          was not included in the monitor entry.
   *
   * @deprecated  Use {@link #getLastCheckpointStopTime()} instead.
   */
  @Deprecated()
  @SuppressWarnings("deprecation")
  @Nullable()
  public Date getLastCheckpointTime()
  {
    return lastCheckpointTime;
  }



  /**
   * Retrieves the length of time in milliseconds since the last completed
   * checkpoint.
   *
   * @return  The length of time in milliseconds since the last completed
   *          checkpoint, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getMillisSinceLastCheckpoint()
  {
    return millisSinceLastCheckpoint;
  }



  /**
   * Retrieves the number of log files that the cleaner needs to examine.
   *
   * @return  The number of log files that the cleaner needs to examine, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getCleanerBacklog()
  {
    return cleanerBacklog;
  }



  /**
   * Retrieves the number of nodes that have been evicted from the database
   * cache since the backend was started.
   *
   * @return  The number of nodes that have been evicted from the database cache
   *          since the backend was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Long getNodesEvicted()
  {
    return nodesEvicted;
  }



  /**
   * Retrieves the number of random-access disk reads performed since the
   * backend was started.
   *
   * @return  The number of random-access disk reads performed since the backend
   *          was started, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getRandomReads()
  {
    return randomReads;
  }



  /**
   * Retrieves the number of random-access disk writes performed since the
   * backend was started.
   *
   * @return  The number of random-access disk writes performed since the
   *          backend was started, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getRandomWrites()
  {
    return randomWrites;
  }



  /**
   * Retrieves the number of sequential disk reads performed since the backend
   * was started.
   *
   * @return  The number of sequential disk reads performed since the backend
   *          was started, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getSequentialReads()
  {
    return sequentialReads;
  }



  /**
   * Retrieves the number of sequential disk writes performed since the backend
   * was started.
   *
   * @return  The number of sequential disk writes performed since the backend
   *          was started, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getSequentialWrites()
  {
    return sequentialWrites;
  }



  /**
   * Retrieves the number of active transactions in the JE database environment.
   *
   * @return  The number of active transactions in the JE database environment,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getActiveTransactionCount()
  {
    return activeTransactionCount;
  }



  /**
   * Retrieves the number of read locks held in the JE database environment.
   *
   * @return  The number of read locks held in the JE database environment, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getReadLocksHeld()
  {
    return readLocksHeld;
  }



  /**
   * Retrieves the number of write locks held in the JE database environment.
   *
   * @return  The number of write locks held in the JE database environment, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getWriteLocksHeld()
  {
    return writeLocksHeld;
  }



  /**
   * Retrieves the number of transactions currently waiting on a lock in the
   * database environment.
   *
   * @return  The number of transactions currently waiting on a lock in the
   *          database environment, or {@code null} if it was not included in
   *          the monitor entry.
   */
  @Nullable()
  public Long getTransactionsWaitingOnLocks()
  {
    return transactionsWaitingOnLocks;
  }



  /**
   * Retrieves a set of general environment statistics for the database
   * environment, mapped from the statistic name to the string representation of
   * its value.  The statistic names will be formatted in all lowercase
   * characters.
   *
   * @return  A set of general environment statistics for the database
   *          environment, mapped from the statistic name to the string
   *          representation of its value.
   */
  @NotNull()
  public Map<String,String> getEnvironmentStats()
  {
    return envStats;
  }



  /**
   * Retrieves the string representation of the value for a database environment
   * statistic.
   *
   * @param  statName  The name of the statistic to retrieve.  It will be
   *                   treated in a case-insensitive manner.
   *
   * @return  The value of the requested database environment statistic, or
   *          {@code null} if no such statistic was provided.
   */
  @Nullable()
  public String getEnvironmentStat(@NotNull final String statName)
  {
    return envStats.get(StaticUtils.toLowerCase(statName));
  }



  /**
   * Retrieves a set of lock statistics for the database environment, mapped
   * from the statistic name to the string representation of its value.  The
   * statistic names will be formatted in all lowercase characters.
   *
   * @return  A set of lock statistics for the database environment, mapped from
   *          the statistic name to the string representation of its value.
   */
  @NotNull()
  public Map<String,String> getLockStats()
  {
    return lockStats;
  }



  /**
   * Retrieves the string representation of the value for a database environment
   * lock statistic.
   *
   * @param  statName  The name of the statistic to retrieve.  It will be
   *                   treated in a case-insensitive manner.
   *
   * @return  The value of the requested database environment lock statistic, or
   *          {@code null} if no such statistic was provided.
   */
  @Nullable()
  public String getLockStat(@NotNull final String statName)
  {
    return lockStats.get(StaticUtils.toLowerCase(statName));
  }



  /**
   * Retrieves a set of transaction statistics for the database environment,
   * mapped from the statistic name to the string representation of its value.
   * The statistic names will be formatted in all lowercase characters.
   *
   * @return  A set of transaction statistics for the database environment,
   *          mapped from the statistic name to the string representation of its
   *          value.
   */
  @NotNull()
  public Map<String,String> getTransactionStats()
  {
    return txnStats;
  }



  /**
   * Retrieves the string representation of the value for a database environment
   * transaction statistic.
   *
   * @param  statName  The name of the statistic to retrieve.  It will be
   *                   treated in a case-insensitive manner.
   *
   * @return  The value of the requested database environment transaction
   *          statistic, or {@code null} if no such statistic was provided.
   */
  @Nullable()
  public String getTransactionStat(@NotNull final String statName)
  {
    return txnStats.get(StaticUtils.toLowerCase(statName));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_JE_ENVIRONMENT_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_JE_ENVIRONMENT_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));

    if (backendID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BACKEND_ID,
           INFO_JE_ENVIRONMENT_DISPNAME_BACKEND_ID.get(),
           INFO_JE_ENVIRONMENT_DESC_BACKEND_ID.get(),
           backendID);
    }

    if (jeVersion != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JE_VERSION,
           INFO_JE_ENVIRONMENT_DISPNAME_JE_VERSION.get(),
           INFO_JE_ENVIRONMENT_DESC_JE_VERSION.get(),
           jeVersion);
    }

    if (dbDirectory != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DB_DIRECTORY,
           INFO_JE_ENVIRONMENT_DISPNAME_DB_DIRECTORY.get(),
           INFO_JE_ENVIRONMENT_DESC_DB_DIRECTORY.get(),
           dbDirectory);
    }

    if (dbOnDiskSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DB_ON_DISK_SIZE,
           INFO_JE_ENVIRONMENT_DISPNAME_DB_ON_DISK_SIZE.get(),
           INFO_JE_ENVIRONMENT_DESC_DB_ON_DISK_SIZE.get(),
           dbOnDiskSize);
    }

    if (currentDBCacheSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_CACHE_SIZE,
           INFO_JE_ENVIRONMENT_DISPNAME_CURRENT_CACHE_SIZE.get(),
           INFO_JE_ENVIRONMENT_DESC_CURRENT_CACHE_SIZE.get(),
           currentDBCacheSize);
    }

    if (maxDBCacheSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_CACHE_SIZE,
           INFO_JE_ENVIRONMENT_DISPNAME_MAX_CACHE_SIZE.get(),
           INFO_JE_ENVIRONMENT_DESC_MAX_CACHE_SIZE.get(),
           maxDBCacheSize);
    }

    if (dbCachePercentFull != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CACHE_PCT_FULL,
           INFO_JE_ENVIRONMENT_DISPNAME_CACHE_PCT_FULL.get(),
           INFO_JE_ENVIRONMENT_DESC_CACHE_PCT_FULL.get(),
           dbCachePercentFull);
    }

    if (checkpointInProgress != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CHECKPOINT_IN_PROGRESS,
           INFO_JE_ENVIRONMENT_DISPNAME_CP_IN_PROGRESS.get(),
           INFO_JE_ENVIRONMENT_DESC_CP_IN_PROGRESS.get(),
           checkpointInProgress);
    }

    if (numCheckpoints != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_CHECKPOINTS,
           INFO_JE_ENVIRONMENT_DISPNAME_NUM_CP.get(),
           INFO_JE_ENVIRONMENT_DESC_NUM_CP.get(),
           numCheckpoints);
    }

    if (totalCheckpointDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_CHECKPOINT_DURATION_MILLIS,
           INFO_JE_ENVIRONMENT_DISPNAME_TOTAL_CP_DURATION.get(),
           INFO_JE_ENVIRONMENT_DESC_TOTAL_CP_DURATION.get(),
           totalCheckpointDurationMillis);
    }

    if (averageCheckpointDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_AVERAGE_CHECKPOINT_DURATION_MILLIS,
           INFO_JE_ENVIRONMENT_DISPNAME_AVG_CP_DURATION.get(),
           INFO_JE_ENVIRONMENT_DESC_AVG_CP_DURATION.get(),
           averageCheckpointDurationMillis);
    }

    if (lastCheckpointDurationMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LAST_CHECKPOINT_DURATION_MILLIS,
           INFO_JE_ENVIRONMENT_DISPNAME_LAST_CP_DURATION.get(),
           INFO_JE_ENVIRONMENT_DESC_LAST_CP_DURATION.get(),
           lastCheckpointDurationMillis);
    }

    if (lastCheckpointStartTime != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LAST_CHECKPOINT_START_TIME,
           INFO_JE_ENVIRONMENT_DISPNAME_LAST_CP_START_TIME.get(),
           INFO_JE_ENVIRONMENT_DESC_LAST_CP_START_TIME.get(),
           lastCheckpointStartTime);
    }

    if (lastCheckpointStopTime != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LAST_CHECKPOINT_STOP_TIME,
           INFO_JE_ENVIRONMENT_DISPNAME_LAST_CP_STOP_TIME.get(),
           INFO_JE_ENVIRONMENT_DESC_LAST_CP_STOP_TIME.get(),
           lastCheckpointStopTime);
    }

    if (millisSinceLastCheckpoint != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MILLIS_SINCE_LAST_CHECKPOINT,
           INFO_JE_ENVIRONMENT_DISPNAME_MILLIS_SINCE_CP.get(),
           INFO_JE_ENVIRONMENT_DESC_MILLIS_SINCE_CP.get(),
           millisSinceLastCheckpoint);
    }

    if (cleanerBacklog != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CLEANER_BACKLOG,
           INFO_JE_ENVIRONMENT_DISPNAME_CLEANER_BACKLOG.get(),
           INFO_JE_ENVIRONMENT_DESC_CLEANER_BACKLOG.get(),
           cleanerBacklog);
    }

    if (nodesEvicted != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NODES_EVICTED,
           INFO_JE_ENVIRONMENT_DISPNAME_NODES_EVICTED.get(),
           INFO_JE_ENVIRONMENT_DESC_NODES_EVICTED.get(),
           nodesEvicted);
    }

    if (randomReads != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RANDOM_READS,
           INFO_JE_ENVIRONMENT_DISPNAME_RANDOM_READS.get(),
           INFO_JE_ENVIRONMENT_DESC_RANDOM_READS.get(),
           randomReads);
    }

    if (randomWrites != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RANDOM_WRITES,
           INFO_JE_ENVIRONMENT_DISPNAME_RANDOM_WRITES.get(),
           INFO_JE_ENVIRONMENT_DESC_RANDOM_WRITES.get(),
           randomWrites);
    }

    if (sequentialReads != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEQUENTIAL_READS,
           INFO_JE_ENVIRONMENT_DISPNAME_SEQUENTIAL_READS.get(),
           INFO_JE_ENVIRONMENT_DESC_SEQUENTIAL_READS.get(),
           sequentialReads);
    }

    if (sequentialWrites != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEQUENTIAL_WRITES,
           INFO_JE_ENVIRONMENT_DISPNAME_SEQUENTIAL_WRITES.get(),
           INFO_JE_ENVIRONMENT_DESC_SEQUENTIAL_WRITES.get(),
           sequentialWrites);
    }

    if (activeTransactionCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ACTIVE_TXNS,
           INFO_JE_ENVIRONMENT_DISPNAME_ACTIVE_TXNS.get(),
           INFO_JE_ENVIRONMENT_DESC_ACTIVE_TXNS.get(),
           activeTransactionCount);
    }

    if (readLocksHeld != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_READ_LOCKS,
           INFO_JE_ENVIRONMENT_DISPNAME_READ_LOCKS.get(),
           INFO_JE_ENVIRONMENT_DESC_READ_LOCKS.get(),
           readLocksHeld);
    }

    if (writeLocksHeld != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_WRITE_LOCKS,
           INFO_JE_ENVIRONMENT_DISPNAME_WRITE_LOCKS.get(),
           INFO_JE_ENVIRONMENT_DESC_WRITE_LOCKS.get(),
           writeLocksHeld);
    }

    if (transactionsWaitingOnLocks != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_WAITING_TXNS,
           INFO_JE_ENVIRONMENT_DISPNAME_TXNS_WAITING_ON_LOCKS.get(),
           INFO_JE_ENVIRONMENT_DESC_TXNS_WAITING_ON_LOCKS.get(),
           transactionsWaitingOnLocks);
    }

    if (! envStats.isEmpty())
    {
      final ArrayList<String> values = new ArrayList<>(envStats.size());
      for (final Map.Entry<String,String> e : envStats.entrySet())
      {
        values.add(e.getKey() + '=' + e.getValue());
      }

      addMonitorAttribute(attrs,
           PROPERTY_ENV_STATS,
           INFO_JE_ENVIRONMENT_DISPNAME_ENV_STATS.get(),
           INFO_JE_ENVIRONMENT_DESC_ENV_STATS.get(),
           values);
    }

    if (! lockStats.isEmpty())
    {
      final ArrayList<String> values = new ArrayList<>(lockStats.size());
      for (final Map.Entry<String,String> e : lockStats.entrySet())
      {
        values.add(e.getKey() + '=' + e.getValue());
      }

      addMonitorAttribute(attrs,
           PROPERTY_LOCK_STATS,
           INFO_JE_ENVIRONMENT_DISPNAME_LOCK_STATS.get(),
           INFO_JE_ENVIRONMENT_DESC_LOCK_STATS.get(),
           values);
    }

    if (! txnStats.isEmpty())
    {
      final ArrayList<String> values = new ArrayList<>(txnStats.size());
      for (final Map.Entry<String,String> e : txnStats.entrySet())
      {
        values.add(e.getKey() + '=' + e.getValue());
      }

      addMonitorAttribute(attrs,
           PROPERTY_TXN_STATS,
           INFO_JE_ENVIRONMENT_DISPNAME_TXN_STATS.get(),
           INFO_JE_ENVIRONMENT_DESC_TXN_STATS.get(),
           values);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
