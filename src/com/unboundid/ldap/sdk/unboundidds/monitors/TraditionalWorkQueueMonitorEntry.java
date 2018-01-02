/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the state
 * of the traditional work queue.  For all practical purposes, the traditional
 * work queue has been replaced by the UnboundID Work Queue, which is the
 * default work queue implementation (which exposes its own monitor information
 * that can be accessed using the {@link UnboundIDWorkQueueMonitorEntry}).
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * In the event that the traditional work queue is configured for use instead of
 * the UnboundID work queue, then this monitor entry may be used to access the
 * information that it provides, which may include:
 * <UL>
 *   <LI>The total number of requests submitted to the work queue.</LI>
 *   <LI>The number of requests that were rejected because the work queue was
 *       already at its maximum capacity.</LI>
 *   <LI>The number of operations currently held in the work queue waiting to be
 *       picked for processing by a worker thread.</LI>
 *   <LI>The average number of operations held in the work queue since startup
 *       as observed from periodic polling.</LI>
 *   <LI>The maximum number of operations held in the work queue at any time
 *       since startup as observed from periodic polling.</LI>
 * </UL>
 * The server should present at most one traditional work queue monitor entry.
 * It can be retrieved using the
 * {@link MonitorManager#getTraditionalWorkQueueMonitorEntry} method.  This
 * entry provides specific methods for accessing information about the state of
 * the work queue (e.g., the
 * {@link TraditionalWorkQueueMonitorEntry#getCurrentBacklog} method may be used
 * to retrieve the number of operations currently held in the work queue).
 * Alternately, this information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TraditionalWorkQueueMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in LDAP statistics monitor entries.
   */
  static final String TRADITIONAL_WORK_QUEUE_MONITOR_OC =
       "ds-traditional-work-queue-monitor-entry";



  /**
   * The name of the attribute that contains the average observed work queue
   * request backlog.
   */
  private static final String ATTR_AVERAGE_BACKLOG = "averageRequestBacklog";



  /**
   * The name of the attribute that contains the current work queue request
   * backlog.
   */
  private static final String ATTR_CURRENT_BACKLOG = "currentRequestBacklog";



  /**
   * The name of the attribute that contains the maximum observed work queue
   * request backlog.
   */
  private static final String ATTR_MAX_BACKLOG = "maxRequestBacklog";



  /**
   * The name of the attribute that contains the total number of requests that
   * have been rejected because the work queue was full.
   */
  private static final String ATTR_REQUESTS_REJECTED =
       "requestsRejectedDueToQueueFull";



  /**
   * The name of the attribute that contains the total number of requests
   * submitted.
   */
  private static final String ATTR_REQUESTS_SUBMITTED = "requestsSubmitted";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5254676890679281070L;



  // The average work queue backlog.
  private final Long averageBacklog;

  // The current work queue backlog.
  private final Long currentBacklog;

  // The maximum work queue backlog.
  private final Long maxBacklog;

  // The total number of requests rejected due to a full work queue.
  private final Long requestsRejected;

  // The total number of requests submitted.
  private final Long requestsSubmitted;



  /**
   * Creates a new traditional work queue monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a traditional work queue monitor
   *                entry.  It must not be {@code null}.
   */
  public TraditionalWorkQueueMonitorEntry(final Entry entry)
  {
    super(entry);

    averageBacklog    = getLong(ATTR_AVERAGE_BACKLOG);
    currentBacklog    = getLong(ATTR_CURRENT_BACKLOG);
    maxBacklog        = getLong(ATTR_MAX_BACKLOG);
    requestsRejected  = getLong(ATTR_REQUESTS_REJECTED);
    requestsSubmitted = getLong(ATTR_REQUESTS_SUBMITTED);
  }



  /**
   * Retrieves the average number of operations observed in the work queue.
   *
   * @return  The average number of operations observed in the work queue, or
   *          {@code null} if that information was not included in the monitor
   *          entry.
   */
  public Long getAverageBacklog()
  {
    return averageBacklog;
  }



  /**
   * Retrieves the number of operations that are currently in the work queue
   * waiting to be processed.
   *
   * @return  The number of operations that are currently in the work queue
   *          waiting to be processed, or {@code null} if that information was
   *          not included in the monitor entry.
   */
  public Long getCurrentBacklog()
  {
    return currentBacklog;
  }



  /**
   * Retrieves the maximum number of operations observed in the work queue at
   * any given time.
   *
   * @return  The total number of operations observed in the work queue at any
   *          given time, or {@code null} if that information was not included
   *          in the monitor entry.
   */
  public Long getMaxBacklog()
  {
    return maxBacklog;
  }



  /**
   * Retrieves the total number of operation requests that were rejected because
   * the work queue was at its maximum capacity.
   *
   * @return  The total number of operation requests rejected because the work
   *          queue was at its maximum capacity, or {@code null} if that
   *          information was not included in the monitor entry.
   */
  public Long getRequestsRejectedDueToQueueFull()
  {
    return requestsRejected;
  }



  /**
   * Retrieves the total number of operation requests submitted to the work
   * queue.
   *
   * @return  The total number of operation requests submitted to the work
   *          queue, or {@code null} if that information was not included in the
   *          monitor entry.
   */
  public Long getRequestsSubmitted()
  {
    return requestsSubmitted;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDisplayName()
  {
    return INFO_TRADITIONAL_WORK_QUEUE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDescription()
  {
    return INFO_TRADITIONAL_WORK_QUEUE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<String,MonitorAttribute>();

    if (requestsSubmitted != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUESTS_SUBMITTED,
           INFO_TRADITIONAL_WORK_QUEUE_DISPNAME_REQUESTS_SUBMITTED.get(),
           INFO_TRADITIONAL_WORK_QUEUE_DESC_REQUESTS_SUBMITTED.get(),
           requestsSubmitted);
    }

    if (requestsRejected != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REQUESTS_REJECTED,
           INFO_TRADITIONAL_WORK_QUEUE_DISPNAME_REQUESTS_REJECTED.get(),
           INFO_TRADITIONAL_WORK_QUEUE_DESC_REQUESTS_REJECTED.get(),
           requestsRejected);
    }

    if (currentBacklog != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_BACKLOG,
           INFO_TRADITIONAL_WORK_QUEUE_DISPNAME_CURRENT_BACKLOG.get(),
           INFO_TRADITIONAL_WORK_QUEUE_DESC_CURRENT_BACKLOG.get(),
           currentBacklog);
    }

    if (averageBacklog != null)
    {
      addMonitorAttribute(attrs,
           ATTR_AVERAGE_BACKLOG,
           INFO_TRADITIONAL_WORK_QUEUE_DISPNAME_AVERAGE_BACKLOG.get(),
           INFO_TRADITIONAL_WORK_QUEUE_DESC_AVERAGE_BACKLOG.get(),
           averageBacklog);
    }

    if (maxBacklog != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_BACKLOG,
           INFO_TRADITIONAL_WORK_QUEUE_DISPNAME_MAX_BACKLOG.get(),
           INFO_TRADITIONAL_WORK_QUEUE_DESC_MAX_BACKLOG.get(),
           maxBacklog);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
