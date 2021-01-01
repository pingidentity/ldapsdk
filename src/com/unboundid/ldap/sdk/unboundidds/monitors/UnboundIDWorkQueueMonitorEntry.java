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



import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the state
 * of the UnboundID work queue.  This has replaced the traditional work queue as
 * the default work queue implementation used by the Directory Server
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
 * The monitor information that it may make available includes:
 * <UL>
 *   <LI>The number of requests that were rejected because the work queue was
 *       already at its maximum capacity.</LI>
 *   <LI>The number of operations currently held in the work queue waiting to be
 *       picked for processing by a worker thread.</LI>
 *   <LI>The average number of operations held in the work queue since startup
 *       as observed from periodic polling.</LI>
 *   <LI>The maximum number of operations held in the work queue at any time
 *       since startup as observed from periodic polling.</LI>
 * </UL>
 * The server should present at most one UnboundID work queue monitor entry.
 * It can be retrieved using the
 * {@link MonitorManager#getUnboundIDWorkQueueMonitorEntry} method.  This entry
 * provides specific methods for accessing information about the state of
 * the work queue (e.g., the
 * {@link UnboundIDWorkQueueMonitorEntry#getCurrentSize} method may be used
 * to retrieve the number of operations currently held in the work queue).
 * Alternately, this information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class UnboundIDWorkQueueMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in LDAP statistics monitor entries.
   */
  @NotNull static final String UNBOUNDID_WORK_QUEUE_MONITOR_OC =
       "ds-unboundid-work-queue-monitor-entry";



  /**
   * The name of the attribute that contains the average worker thread percent
   * busy.
   */
  @NotNull private static final String ATTR_AVERAGE_QUEUE_TIME_MILLIS =
       "average-operation-queue-time-millis";



  /**
   * The name of the attribute that contains the average worker thread percent
   * busy.
   */
  @NotNull private static final String ATTR_AVERAGE_PCT_BUSY =
       "average-worker-thread-percent-busy";



  /**
   * The name of the attribute that contains the average observed work queue
   * size.
   */
  @NotNull private static final String ATTR_AVERAGE_SIZE = "average-queue-size";



  /**
   * The name of the attribute that contains the current work queue size.
   */
  @NotNull private static final String ATTR_CURRENT_PCT_BUSY =
       "current-worker-thread-percent-busy";



  /**
   * The name of the attribute that contains the current work queue size.
   */
  @NotNull private static final String ATTR_CURRENT_SIZE = "current-queue-size";



  /**
   * The name of the attribute that contains the maximum observed work queue
   * size.
   */
  @NotNull private static final String ATTR_MAX_SIZE = "max-queue-size";



  /**
   * The name of the attribute that contains the maximum worker thread percent
   * busy.
   */
  @NotNull private static final String ATTR_MAX_PCT_BUSY =
       "max-worker-thread-percent-busy";



  /**
   * The name of the attribute that contains the number of busy worker threads.
   */
  @NotNull private static final String ATTR_NUM_BUSY_WORKER_THREADS =
       "num-busy-worker-threads";



  /**
   * The name of the attribute that contains the number of worker threads.
   */
  @NotNull private static final String ATTR_NUM_WORKER_THREADS =
       "num-worker-threads";



  /**
   * The name of the attribute that contains the average worker thread percent
   * busy.
   */
  @NotNull private static final String ATTR_RECENT_AVERAGE_SIZE =
       "recent-average-queue-size";



  /**
   * The name of the attribute that contains the average worker thread percent
   * busy.
   */
  @NotNull private static final String ATTR_RECENT_QUEUE_TIME_MILLIS =
       "recent-operation-queue-time-millis";



  /**
   * The name of the attribute that contains the recent worker thread percent
   * busy.
   */
  @NotNull private static final String ATTR_RECENT_PCT_BUSY =
       "recent-worker-thread-percent-busy";



  /**
   * The name of the attribute that contains the total number of requests that
   * have been rejected because the work queue was full.
   */
  @NotNull private static final String ATTR_REQUESTS_REJECTED =
       "rejected-count";



  /**
   * The name of the attribute that contains the total number of requests that
   * have were stolen from their primary queue by a worker thread associated
   * with a different queue.
   */
  @NotNull private static final String ATTR_REQUESTS_STOLEN = "stolen-count";



  /**
   * The name of the attribute that contains the current size of the work queue
   * reserved for operations processed as part of administrative sessions.
   */
  @NotNull private static final String ATTR_CURRENT_ADMIN_QUEUE_SIZE =
       "current-administrative-session-queue-size";



  /**
   * The name of the attribute that contains the number of worker threads that
   * are currently busy processing operations as part of an administrative
   * session.
   */
  @NotNull private static final String ATTR_MAX_ADMIN_SESSION_QUEUE_SIZE =
       "max-administrative-session-queue-size";



  /**
   * The name of the attribute that contains the total number of worker threads
   * reserved for processing operations that are part of an administrative
   * session.
   */
  @NotNull private static final String ATTR_NUM_ADMIN_WORKER_THREADS =
       "num-administrative-session-worker-threads";



  /**
   * The name of the attribute that contains the number of worker threads that
   * are currently busy processing operations as part of an administrative
   * session.
   */
  @NotNull private static final String ATTR_NUM_BUSY_ADMIN_WORKER_THREADS =
       "num-busy-administrative-session-worker-threads";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -304216058351812232L;



  // The average queue time in milliseconds.
  @Nullable private final Long averageQueueTimeMillis;

  // The average worker thread percent busy.
  @Nullable private final Long averagePercentBusy;

  // The average work queue size.
  @Nullable private final Long averageSize;

  // The current administrative session work queue size.
  @Nullable private final Long currentAdminSize;

  // The current work queue size.
  @Nullable private final Long currentSize;

  // The current worker thread percent busy.
  @Nullable private final Long currentPercentBusy;

  // The maximum administrative session work queue size.
  @Nullable private final Long maxAdminSize;

  // The maximum worker thread percent busy.
  @Nullable private final Long maxPercentBusy;

  // The maximum work queue size.
  @Nullable private final Long maxSize;

  // The number of administrative session worker threads.
  @Nullable private final Long numAdminWorkerThreads;

  // The number of busy worker threads.
  @Nullable private final Long numBusyWorkerThreads;

  // The number of busy administrative session worker threads.
  @Nullable private final Long numBusyAdminWorkerThreads;

  // The number of worker threads.
  @Nullable private final Long numWorkerThreads;

  // The recent average work queue size.
  @Nullable private final Long recentAverageSize;

  // The recent queue time in milliseconds.
  @Nullable private final Long recentQueueTimeMillis;

  // The recent worker thread percent busy.
  @Nullable private final Long recentPercentBusy;

  // The total number of requests rejected due to a full work queue.
  @Nullable private final Long requestsRejected;

  // The total number of requests rejected due to a full work queue.
  @Nullable private final Long requestsStolen;



  /**
   * Creates a new UnboundID work queue monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a traditional work queue monitor
   *                entry.  It must not be {@code null}.
   */
  public UnboundIDWorkQueueMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    averageSize               = getLong(ATTR_AVERAGE_SIZE);
    currentSize               = getLong(ATTR_CURRENT_SIZE);
    recentAverageSize         = getLong(ATTR_RECENT_AVERAGE_SIZE);
    maxSize                   = getLong(ATTR_MAX_SIZE);
    requestsRejected          = getLong(ATTR_REQUESTS_REJECTED);
    requestsStolen            = getLong(ATTR_REQUESTS_STOLEN);
    numBusyWorkerThreads      = getLong(ATTR_NUM_BUSY_WORKER_THREADS);
    numWorkerThreads          = getLong(ATTR_NUM_WORKER_THREADS);
    currentPercentBusy        = getLong(ATTR_CURRENT_PCT_BUSY);
    averagePercentBusy        = getLong(ATTR_AVERAGE_PCT_BUSY);
    recentPercentBusy         = getLong(ATTR_RECENT_PCT_BUSY);
    maxPercentBusy            = getLong(ATTR_MAX_PCT_BUSY);
    averageQueueTimeMillis    = getLong(ATTR_AVERAGE_QUEUE_TIME_MILLIS);
    recentQueueTimeMillis     = getLong(ATTR_RECENT_QUEUE_TIME_MILLIS);
    currentAdminSize          = getLong(ATTR_CURRENT_ADMIN_QUEUE_SIZE);
    maxAdminSize              = getLong(ATTR_MAX_ADMIN_SESSION_QUEUE_SIZE);
    numAdminWorkerThreads     = getLong(ATTR_NUM_ADMIN_WORKER_THREADS);
    numBusyAdminWorkerThreads = getLong(ATTR_NUM_BUSY_ADMIN_WORKER_THREADS);
  }



  /**
   * Retrieves the average number of operations observed in the work queue.
   *
   * @return  The average number of operations observed in the work queue, or
   *          {@code null} if that information was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getAverageSize()
  {
    return averageSize;
  }



  /**
   * Retrieves the average number of operations observed in the work queue over
   * a recent interval.
   *
   * @return  The average number of operations observed in the work queue over a
   *          recent interval, or {@code null} if that information was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Long getRecentAverageSize()
  {
    return recentAverageSize;
  }



  /**
   * Retrieves the number of operations that are currently in the work queue
   * waiting to be processed.
   *
   * @return  The number of operations that are currently in the work queue
   *          waiting to be processed, or {@code null} if that information was
   *          not included in the monitor entry.
   */
  @Nullable()
  public Long getCurrentSize()
  {
    return currentSize;
  }



  /**
   * Retrieves the maximum number of operations observed in the work queue at
   * any given time.
   *
   * @return  The total number of operations observed in the work queue at any
   *          given time, or {@code null} if that information was not included
   *          in the monitor entry.
   */
  @Nullable()
  public Long getMaxSize()
  {
    return maxSize;
  }



  /**
   * Retrieves the total number of operation requests that were rejected because
   * the work queue was at its maximum capacity.
   *
   * @return  The total number of operation requests rejected because the work
   *          queue was at its maximum capacity, or {@code null} if that
   *          information was not included in the monitor entry.
   */
  @Nullable()
  public Long getRequestsRejectedDueToQueueFull()
  {
    return requestsRejected;
  }



  /**
   * Retrieves the total number of operation requests that have been stolen from
   * their primary queue by a worker thread associated with a different queue.
   *
   * @return  The total number of operation requests that have been stolen from
   *          their primary queue by a worker thread associated with a different
   *          queue, or {@code null} if that information was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getRequestsStolen()
  {
    return requestsStolen;
  }



  /**
   * Retrieves the number of worker threads configured for the work queue.
   *
   * @return  The number of worker threads configured for the work queue, or
   *          {@code null} if that information was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getNumWorkerThreads()
  {
    return numWorkerThreads;
  }



  /**
   * Retrieves the number of worker threads that are currently busy processing
   * an operation.
   *
   * @return  The number of worker threads that are currently busy processing an
   *          operation, or {@code null} if that information was not included in
   *          the monitor entry.
   */
  @Nullable()
  public Long getNumBusyWorkerThreads()
  {
    return numBusyWorkerThreads;
  }



  /**
   * Retrieves the percentage of worker threads that are currently busy
   * processing an operation.
   *
   * @return  The percentage of worker threads that are currently busy
   *          processing an operation, or {@code null} if that information was
   *          not included in the monitor entry.
   */
  @Nullable()
  public Long getCurrentWorkerThreadPercentBusy()
  {
    return currentPercentBusy;
  }



  /**
   * Retrieves the average percentage of the time since startup that worker
   * threads have spent busy processing operations.
   *
   * @return  The average percentage of the time since startup that worker
   *          threads have spent busy processing operations, or {@code null} if
   *          that information was not included in the monitor entry.
   */
  @Nullable()
  public Long getAverageWorkerThreadPercentBusy()
  {
    return averagePercentBusy;
  }



  /**
   * Retrieves the percentage of the time over a recent interval that worker
   * threads have spent busy processing operations.
   *
   * @return  The percentage of the time over a recent interval that worker
   *          threads have spent busy processing operations, or {@code null} if
   *          that information was not included in the monitor entry.
   */
  @Nullable()
  public Long getRecentWorkerThreadPercentBusy()
  {
    return recentPercentBusy;
  }



  /**
   * Retrieves the maximum percentage of the time over any interval that worker
   * threads have spent busy processing operations.
   *
   * @return  The maximum percentage of the time over any interval that worker
   *          threads have spent busy processing operations, or {@code null} if
   *          that information was not included in the monitor entry.
   */
  @Nullable()
  public Long getMaxWorkerThreadPercentBusy()
  {
    return maxPercentBusy;
  }



  /**
   * Retrieves the average length of time in milliseconds that operations have
   * been required to wait on the work queue before being picked up by a worker
   * thread.
   *
   * @return  The average length of time in milliseconds that operations have
   *          been required to wait on the work queue, or {@code null} if that
   *          information was not included in the monitor entry.
   */
  @Nullable()
  public Long getAverageOperationQueueTimeMillis()
  {
    return averageQueueTimeMillis;
  }



  /**
   * Retrieves the average length of time in milliseconds that
   * recently-processed operations have been required to wait on the work queue
   * before being picked up by a worker thread.
   *
   * @return  The average length of time in milliseconds that recently-processed
   *          operations have been required to wait on the work queue, or
   *          {@code null} if that information was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getRecentOperationQueueTimeMillis()
  {
    return recentQueueTimeMillis;
  }



  /**
   * Retrieves the number of operations that are currently waiting to be
   * processed in the portion of the work queue reserved for operations that are
   * part of an administrative session.
   *
   * @return  The number of operations that are currently waiting to be
   *          processed in the portion of the work queue reserved for operations
   *          that are part of an administrative session, or {@code null} if
   *          that information was not included in the monitor entry.
   */
  @Nullable()
  public Long getCurrentAdministrativeSessionQueueSize()
  {
    return currentAdminSize;
  }



  /**
   * Retrieves the maximum number of operations observed in the dedicated
   * administrative session queue at any given time.
   *
   * @return  The total number of operations observed in the dedicated
   *          administrative session queue at any given time, or {@code null} if
   *          that information was not included in the monitor entry.
   */
  @Nullable()
  public Long getMaxAdministrativeSessionQueueSize()
  {
    return maxAdminSize;
  }



  /**
   * Retrieves the number of worker threads that have been reserved for
   * processing operations that are part of an administrative session.
   *
   * @return  The number of worker threads that have been reserved for
   *          processing operations that are part of an administrative session,
   *          or {@code null} if that information was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getNumAdministrativeSessionWorkerThreads()
  {
    return numAdminWorkerThreads;
  }



  /**
   * Retrieves the number of worker threads that are currently busy processing
   * an operation which is part of an administrative session.
   *
   * @return  The number of worker threads that are currently busy processing an
   *          operation which is part of an administrative session, or
   *          {@code null} if that information was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getNumBusyAdministrativeSessionWorkerThreads()
  {
    return numBusyAdminWorkerThreads;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_UNBOUNDID_WORK_QUEUE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_UNBOUNDID_WORK_QUEUE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(50));

    if (requestsRejected != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUESTS_REJECTED,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_REQUESTS_REJECTED.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_REQUESTS_REJECTED.get(),
           requestsRejected);
    }

    if (requestsStolen != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUESTS_STOLEN,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_REQUESTS_STOLEN.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_REQUESTS_STOLEN.get(),
           requestsStolen);
    }

    if (currentSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_SIZE,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_CURRENT_SIZE.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_CURRENT_SIZE.get(),
           currentSize);
    }

    if (recentAverageSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_AVERAGE_SIZE,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_RECENT_AVERAGE_SIZE.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_RECENT_AVERAGE_SIZE.get(),
           recentAverageSize);
    }

    if (averageSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_AVERAGE_SIZE,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_AVERAGE_SIZE.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_AVERAGE_SIZE.get(),
           averageSize);
    }

    if (maxSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_SIZE,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_MAX_SIZE.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_MAX_SIZE.get(),
           maxSize);
    }

    if (numWorkerThreads != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_WORKER_THREADS,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_NUM_THREADS.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_NUM_THREADS.get(),
           numWorkerThreads);
    }

    if (numBusyWorkerThreads != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_BUSY_WORKER_THREADS,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_NUM_BUSY_THREADS.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_NUM_BUSY_THREADS.get(),
           numBusyWorkerThreads);
    }

    if (currentPercentBusy != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_PCT_BUSY,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_CURRENT_PCT_BUSY.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_CURRENT_PCT_BUSY.get(),
           currentPercentBusy);
    }

    if (averagePercentBusy != null)
    {
      addMonitorAttribute(attrs,
           ATTR_AVERAGE_PCT_BUSY,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_AVG_PCT_BUSY.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_AVG_PCT_BUSY.get(),
           averagePercentBusy);
    }

    if (recentPercentBusy != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_PCT_BUSY,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_RECENT_PCT_BUSY.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_RECENT_PCT_BUSY.get(),
           recentPercentBusy);
    }

    if (maxPercentBusy != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_PCT_BUSY,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_MAX_PCT_BUSY.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_MAX_PCT_BUSY.get(),
           maxPercentBusy);
    }

    if (averageQueueTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_AVERAGE_QUEUE_TIME_MILLIS,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_AVG_QUEUE_TIME.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_AVG_QUEUE_TIME.get(),
           averageQueueTimeMillis);
    }

    if (recentQueueTimeMillis != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECENT_QUEUE_TIME_MILLIS,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_RECENT_QUEUE_TIME.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_RECENT_QUEUE_TIME.get(),
           recentQueueTimeMillis);
    }

    if (currentAdminSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_ADMIN_QUEUE_SIZE,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_CURRENT_ADMIN_QUEUE_SIZE.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_CURRENT_ADMIN_QUEUE_SIZE.get(),
           currentAdminSize);
    }

    if (maxAdminSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_ADMIN_SESSION_QUEUE_SIZE,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_MAX_ADMIN_QUEUE_SIZE.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_MAX_ADMIN_QUEUE_SIZE.get(),
           maxAdminSize);
    }

    if (numAdminWorkerThreads != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_ADMIN_WORKER_THREADS,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_NUM_ADMIN_THREADS.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_NUM_ADMIN_THREADS.get(),
           numAdminWorkerThreads);
    }

    if (numBusyAdminWorkerThreads != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_BUSY_ADMIN_WORKER_THREADS,
           INFO_UNBOUNDID_WORK_QUEUE_DISPNAME_NUM_BUSY_ADMIN_THREADS.get(),
           INFO_UNBOUNDID_WORK_QUEUE_DESC_NUM_BUSY_ADMIN_THREADS.get(),
           numBusyAdminWorkerThreads);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
