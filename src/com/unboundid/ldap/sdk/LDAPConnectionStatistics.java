/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.text.DecimalFormat;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure with information about operations
 * performed on an associated LDAP connection.  Calls to update statistics
 * maintained by this class are threadsafe, but attempts to access different
 * statistics may not be consistent if other operations may be in progress on
 * the connection.
 * <BR><BR>
 * The set of statistics maintained for connections:
 * <UL>
 *   <LI>The number of attempts made to establish the connection.</LI>
 *   <LI>The number of times the connection has been closed.</LI>
 *   <LI>The number of requests of each type that have been sent over the
 *       connection.</LI>
 *   <LI>The number of responses of each type that have been received over the
 *       connection.</LI>
 *   <LI>The average response time (in milliseconds or nanoseconds) for each
 *       type of operation processed on the connection.</LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
public final class LDAPConnectionStatistics
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1096417617572481790L;



  // The number of abandon requests sent over the associated connection.
  @NotNull private final AtomicLong numAbandonRequests;

  // The number of add requests sent over the associated connection.
  @NotNull private final AtomicLong numAddRequests;

  // The number of add responses received on the associated connection.
  @NotNull private final AtomicLong numAddResponses;

  // The number of bind requests sent over the associated connection.
  @NotNull private final AtomicLong numBindRequests;

  // The number of bind responses received on the associated connection.
  @NotNull private final AtomicLong numBindResponses;

  // The number of compare requests sent over the associated connection.
  @NotNull private final AtomicLong numCompareRequests;

  // The number of compare responses received on the associated connection.
  @NotNull private final AtomicLong numCompareResponses;

  // The number of times the associated connection has been connected to a
  // server.
  @NotNull private final AtomicLong numConnects;

  // The number of delete requests sent over the associated connection.
  @NotNull private final AtomicLong numDeleteRequests;

  // The number of delete responses received on the associated connection.
  @NotNull private final AtomicLong numDeleteResponses;

  // The number of times the associated connection has been disconnected from a
  // server.
  @NotNull private final AtomicLong numDisconnects;

  // The number of extended requests sent over the associated connection.
  @NotNull private final AtomicLong numExtendedRequests;

  // The number of extended responses received on the associated connection.
  @NotNull private final AtomicLong numExtendedResponses;

  // The number of modify requests sent over the associated connection.
  @NotNull private final AtomicLong numModifyRequests;

  // The number of modify responses received on the associated connection.
  @NotNull private final AtomicLong numModifyResponses;

  // The number of modify DN requests sent over the associated connection.
  @NotNull private final AtomicLong numModifyDNRequests;

  // The number of modify DN responses received on the associated connection.
  @NotNull private final AtomicLong numModifyDNResponses;

  // The number of search requests sent over the associated connection.
  @NotNull private final AtomicLong numSearchRequests;

  // The number of search result entry responses received on the associated
  // connection.
  @NotNull private final AtomicLong numSearchEntryResponses;

  // The number of search result reference responses received on the associated
  // connection.
  @NotNull private final AtomicLong numSearchReferenceResponses;

  // The number of search result done responses received on the associated
  // connection.
  @NotNull private final AtomicLong numSearchDoneResponses;

  // The number of unbind requests sent over the associated connection.
  @NotNull private final AtomicLong numUnbindRequests;

  // The total length of time spent waiting for add responses.
  @NotNull private final AtomicLong totalAddResponseTime;

  // The total length of time spent waiting for bind responses.
  @NotNull private final AtomicLong totalBindResponseTime;

  // The total length of time spent waiting for compare responses.
  @NotNull private final AtomicLong totalCompareResponseTime;

  // The total length of time spent waiting for delete responses.
  @NotNull private final AtomicLong totalDeleteResponseTime;

  // The total length of time spent waiting for extended responses.
  @NotNull private final AtomicLong totalExtendedResponseTime;

  // The total length of time spent waiting for modify responses.
  @NotNull private final AtomicLong totalModifyResponseTime;

  // The total length of time spent waiting for modify DN responses.
  @NotNull private final AtomicLong totalModifyDNResponseTime;

  // The total length of time spent waiting for search done responses.
  @NotNull private final AtomicLong totalSearchResponseTime;



  /**
   * Creates a new instance of this LDAP connection statistics object.  All of
   * the counts will be initialized to zero.
   */
  public LDAPConnectionStatistics()
  {
    numAbandonRequests          = new AtomicLong(0L);
    numAddRequests              = new AtomicLong(0L);
    numAddResponses             = new AtomicLong(0L);
    numBindRequests             = new AtomicLong(0L);
    numBindResponses            = new AtomicLong(0L);
    numCompareRequests          = new AtomicLong(0L);
    numCompareResponses         = new AtomicLong(0L);
    numConnects                 = new AtomicLong(0L);
    numDeleteRequests           = new AtomicLong(0L);
    numDeleteResponses          = new AtomicLong(0L);
    numDisconnects              = new AtomicLong(0L);
    numExtendedRequests         = new AtomicLong(0L);
    numExtendedResponses        = new AtomicLong(0L);
    numModifyRequests           = new AtomicLong(0L);
    numModifyResponses          = new AtomicLong(0L);
    numModifyDNRequests         = new AtomicLong(0L);
    numModifyDNResponses        = new AtomicLong(0L);
    numSearchRequests           = new AtomicLong(0L);
    numSearchEntryResponses     = new AtomicLong(0L);
    numSearchReferenceResponses = new AtomicLong(0L);
    numSearchDoneResponses      = new AtomicLong(0L);
    numUnbindRequests           = new AtomicLong(0L);
    totalAddResponseTime        = new AtomicLong(0L);
    totalBindResponseTime       = new AtomicLong(0L);
    totalCompareResponseTime    = new AtomicLong(0L);
    totalDeleteResponseTime     = new AtomicLong(0L);
    totalExtendedResponseTime   = new AtomicLong(0L);
    totalModifyResponseTime     = new AtomicLong(0L);
    totalModifyDNResponseTime   = new AtomicLong(0L);
    totalSearchResponseTime     = new AtomicLong(0L);
  }



  /**
   * Resets all counters back to zero.
   */
  public void reset()
  {
    numAbandonRequests.set(0L);
    numAddRequests.set(0L);
    numAddResponses.set(0L);
    numBindRequests.set(0L);
    numBindResponses.set(0L);
    numCompareRequests.set(0L);
    numCompareResponses.set(0L);
    numConnects.set(0L);
    numDeleteRequests.set(0L);
    numDeleteResponses.set(0L);
    numDisconnects.set(0L);
    numExtendedRequests.set(0L);
    numExtendedResponses.set(0L);
    numModifyRequests.set(0L);
    numModifyResponses.set(0L);
    numModifyDNRequests.set(0L);
    numModifyDNResponses.set(0L);
    numSearchRequests.set(0L);
    numSearchEntryResponses.set(0L);
    numSearchReferenceResponses.set(0L);
    numSearchDoneResponses.set(0L);
    numUnbindRequests.set(0L);
    totalAddResponseTime.set(0L);
    totalBindResponseTime.set(0L);
    totalCompareResponseTime.set(0L);
    totalDeleteResponseTime.set(0L);
    totalExtendedResponseTime.set(0L);
    totalModifyResponseTime.set(0L);
    totalModifyDNResponseTime.set(0L);
    totalSearchResponseTime.set(0L);
  }



  /**
   * Retrieves the number of times an attempt has been made to establish the
   * associated connection.
   *
   * @return  The number of times an attempt has been made to establish the
   *          associated connection.
   */
  public long getNumConnects()
  {
    return numConnects.get();
  }



  /**
   * Increments the number of times an attempt has been made to establish the
   * associated connection.
   */
  void incrementNumConnects()
  {
    numConnects.incrementAndGet();
  }



  /**
   * Retrieves the number of times the associated connection has been
   * terminated.  Note that this may exceed the number of connection attempts
   * because there may be cases in which an attempt is made to close a
   * connection after it has already been closed or otherwise disconnected.
   *
   * @return  The number of times the associated connection has been terminated.
   */
  public long getNumDisconnects()
  {
    return numDisconnects.get();
  }



  /**
   * Increments the number of times an attempt has been made to terminate the
   * associated connection.
   */
  void incrementNumDisconnects()
  {
    numDisconnects.incrementAndGet();
  }



  /**
   * Retrieves the number of abandon requests sent on the associated connection.
   *
   * @return  The number of abandon requests sent on the associated connection.
   */
  public long getNumAbandonRequests()
  {
    return numAbandonRequests.get();
  }



  /**
   * Increments the number of abandon requests sent on the associated
   * connection.
   */
  void incrementNumAbandonRequests()
  {
    numAbandonRequests.incrementAndGet();
  }



  /**
   * Retrieves the number of add requests sent on the associated connection.
   *
   * @return  The number of add requests sent on the associated connection.
   */
  public long getNumAddRequests()
  {
    return numAddRequests.get();
  }



  /**
   * Increments the number of add requests sent on the associated connection.
   */
  void incrementNumAddRequests()
  {
    numAddRequests.incrementAndGet();
  }



  /**
   * Retrieves the number of add responses sent on the associated connection.
   *
   * @return  The number of add responses sent on the associated connection.
   */
  public long getNumAddResponses()
  {
    return numAddResponses.get();
  }



  /**
   * Increments the number of add responses sent on the associated connection.
   *
   * @param  responseTime  The length of time in nanoseconds between sending
   *                       the request and receiving the response.
   */
  void incrementNumAddResponses(final long responseTime)
  {
    numAddResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalAddResponseTime.addAndGet(responseTime);
    }
  }



  /**
   * Retrieves the total response time in nanoseconds for all add operations
   * processed on the associated connection.
   *
   * @return  The total response time in nanoseconds for all add operations
   *          processed on the associated connection.
   */
  public long getTotalAddResponseTimeNanos()
  {
    return totalAddResponseTime.get();
  }



  /**
   * Retrieves the total response time in milliseconds for all add operations
   * processed on the associated connection.
   *
   * @return  The total response time in milliseconds for all add operations
   *          processed on the associated connection.
   */
  public long getTotalAddResponseTimeMillis()
  {
    return Math.round(totalAddResponseTime.get() / 1_000_000.0d);
  }



  /**
   * Retrieves the average response time in nanoseconds for all add operations
   * processed on the associated connection.
   *
   * @return  The average response time in nanoseconds for all add operations
   *          processed on the associated connection, or {@code Double.NaN} if
   *          no add operations have yet been performed.
   */
  public double getAverageAddResponseTimeNanos()
  {
    final long totalTime  = totalAddResponseTime.get();
    final long totalCount = numAddResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the average response time in milliseconds for all add operations
   * processed on the associated connection.
   *
   * @return  The average response time in milliseconds for all add operations
   *          processed on the associated connection, or {@code Double.NaN} if
   *          no add operations have yet been performed.
   */
  public double getAverageAddResponseTimeMillis()
  {
    final long totalTime  = totalAddResponseTime.get();
    final long totalCount = numAddResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1_000_000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the number of bind requests sent on the associated connection.
   *
   * @return  The number of bind requests sent on the associated connection.
   */
  public long getNumBindRequests()
  {
    return numBindRequests.get();
  }



  /**
   * Increments the number of bind requests sent on the associated connection.
   */
  void incrementNumBindRequests()
  {
    numBindRequests.incrementAndGet();
  }



  /**
   * Retrieves the number of bind responses sent on the associated connection.
   *
   * @return  The number of bind responses sent on the associated connection.
   */
  public long getNumBindResponses()
  {
    return numBindResponses.get();
  }



  /**
   * Increments the number of bind responses sent on the associated connection.
   *
   * @param  responseTime  The length of time in nanoseconds between sending
   *                       the request and receiving the response.
   */
  void incrementNumBindResponses(final long responseTime)
  {
    numBindResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalBindResponseTime.addAndGet(responseTime);
    }
  }



  /**
   * Retrieves the total response time in nanoseconds for all bind operations
   * processed on the associated connection.
   *
   * @return  The total response time in nanoseconds for all bind operations
   *          processed on the associated connection.
   */
  public long getTotalBindResponseTimeNanos()
  {
    return totalBindResponseTime.get();
  }



  /**
   * Retrieves the total response time in milliseconds for all bind operations
   * processed on the associated connection.
   *
   * @return  The total response time in milliseconds for all bind operations
   *          processed on the associated connection.
   */
  public long getTotalBindResponseTimeMillis()
  {
    return Math.round(totalBindResponseTime.get() / 1_000_000.0d);
  }



  /**
   * Retrieves the average response time in nanoseconds for all bind operations
   * processed on the associated connection.
   *
   * @return  The average response time in nanoseconds for all bind operations
   *          processed on the associated connection, or {@code Double.NaN} if
   *          no bind operations have yet been performed.
   */
  public double getAverageBindResponseTimeNanos()
  {
    final long totalTime  = totalBindResponseTime.get();
    final long totalCount = numBindResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the average response time in milliseconds for all bind operations
   * processed on the associated connection.
   *
   * @return  The average response time in milliseconds for all bind operations
   *          processed on the associated connection, or {@code Double.NaN} if
   *          no bind operations have yet been performed.
   */
  public double getAverageBindResponseTimeMillis()
  {
    final long totalTime  = totalBindResponseTime.get();
    final long totalCount = numBindResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1_000_000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the number of compare requests sent on the associated connection.
   *
   * @return  The number of compare requests sent on the associated connection.
   */
  public long getNumCompareRequests()
  {
    return numCompareRequests.get();
  }



  /**
   * Increments the number of compare requests sent on the associated
   * connection.
   */
  void incrementNumCompareRequests()
  {
    numCompareRequests.incrementAndGet();
  }



  /**
   * Retrieves the number of compare responses sent on the associated
   * connection.
   *
   * @return  The number of compare responses sent on the associated connection.
   */
  public long getNumCompareResponses()
  {
    return numCompareResponses.get();
  }



  /**
   * Increments the number of compare responses sent on the associated
   * connection.
   *
   * @param  responseTime  The length of time in nanoseconds between sending
   *                       the request and receiving the response.
   */
  void incrementNumCompareResponses(final long responseTime)
  {
    numCompareResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalCompareResponseTime.addAndGet(responseTime);
    }
  }



  /**
   * Retrieves the total response time in nanoseconds for all compare
   * operations processed on the associated connection.
   *
   * @return  The total response time in nanoseconds for all compare operations
   *          processed on the associated connection.
   */
  public long getTotalCompareResponseTimeNanos()
  {
    return totalCompareResponseTime.get();
  }



  /**
   * Retrieves the total response time in milliseconds for all compare
   * operations processed on the associated connection.
   *
   * @return  The total response time in milliseconds for all compare operations
   *          processed on the associated connection.
   */
  public long getTotalCompareResponseTimeMillis()
  {
    return Math.round(totalCompareResponseTime.get() / 1_000_000.0d);
  }



  /**
   * Retrieves the average response time in nanoseconds for all compare
   * operations processed on the associated connection.
   *
   * @return  The average response time in nanoseconds for all compare
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no compare operations have yet been
   *          performed.
   */
  public double getAverageCompareResponseTimeNanos()
  {
    final long totalTime  = totalCompareResponseTime.get();
    final long totalCount = numCompareResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the average response time in milliseconds for all compare
   * operations processed on the associated connection.
   *
   * @return  The average response time in milliseconds for all compare
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no compare operations have yet been
   *          performed.
   */
  public double getAverageCompareResponseTimeMillis()
  {
    final long totalTime  = totalCompareResponseTime.get();
    final long totalCount = numCompareResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1_000_000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the number of delete requests sent on the associated connection.
   *
   * @return  The number of delete requests sent on the associated connection.
   */
  public long getNumDeleteRequests()
  {
    return numDeleteRequests.get();
  }



  /**
   * Increments the number of delete requests sent on the associated connection.
   */
  void incrementNumDeleteRequests()
  {
    numDeleteRequests.incrementAndGet();
  }



  /**
   * Retrieves the number of delete responses sent on the associated connection.
   *
   * @return  The number of delete responses sent on the associated connection.
   */
  public long getNumDeleteResponses()
  {
    return numDeleteResponses.get();
  }



  /**
   * Increments the number of delete responses sent on the associated
   * connection.
   *
   * @param  responseTime  The length of time in nanoseconds between sending
   *                       the request and receiving the response.
   */
  void incrementNumDeleteResponses(final long responseTime)
  {
    numDeleteResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalDeleteResponseTime.addAndGet(responseTime);
    }
  }



  /**
   * Retrieves the total response time in nanoseconds for all delete
   * operations processed on the associated connection.
   *
   * @return  The total response time in nanoseconds for all delete operations
   *          processed on the associated connection.
   */
  public long getTotalDeleteResponseTimeNanos()
  {
    return totalDeleteResponseTime.get();
  }



  /**
   * Retrieves the total response time in milliseconds for all delete
   * operations processed on the associated connection.
   *
   * @return  The total response time in milliseconds for all delete operations
   *          processed on the associated connection.
   */
  public long getTotalDeleteResponseTimeMillis()
  {
    return Math.round(totalDeleteResponseTime.get() / 1_000_000.0d);
  }



  /**
   * Retrieves the average response time in nanoseconds for all delete
   * operations processed on the associated connection.
   *
   * @return  The average response time in nanoseconds for all delete
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no delete operations have yet been
   *          performed.
   */
  public double getAverageDeleteResponseTimeNanos()
  {
    final long totalTime  = totalDeleteResponseTime.get();
    final long totalCount = numDeleteResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the average response time in milliseconds for all delete
   * operations processed on the associated connection.
   *
   * @return  The average response time in milliseconds for all delete
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no delete operations have yet been
   *          performed.
   */
  public double getAverageDeleteResponseTimeMillis()
  {
    final long totalTime  = totalDeleteResponseTime.get();
    final long totalCount = numDeleteResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1_000_000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the number of extended requests sent on the associated
   * connection.
   *
   * @return  The number of extended requests sent on the associated connection.
   */
  public long getNumExtendedRequests()
  {
    return numExtendedRequests.get();
  }



  /**
   * Increments the number of extended requests sent on the associated
   * connection.
   */
  void incrementNumExtendedRequests()
  {
    numExtendedRequests.incrementAndGet();
  }



  /**
   * Retrieves the number of extended responses sent on the associated
   * connection.
   *
   * @return  The number of extended responses sent on the associated
   *          connection.
   */
  public long getNumExtendedResponses()
  {
    return numExtendedResponses.get();
  }



  /**
   * Increments the number of extended responses sent on the associated
   * connection.
   *
   * @param  responseTime  The length of time in nanoseconds between sending
   *                       the request and receiving the response.
   */
  void incrementNumExtendedResponses(final long responseTime)
  {
    numExtendedResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalExtendedResponseTime.addAndGet(responseTime);
    }
  }



  /**
   * Retrieves the total response time in nanoseconds for all extended
   * operations processed on the associated connection.
   *
   * @return  The total response time in nanoseconds for all extended
   *          operations processed on the associated connection.
   */
  public long getTotalExtendedResponseTimeNanos()
  {
    return totalExtendedResponseTime.get();
  }



  /**
   * Retrieves the total response time in milliseconds for all extended
   * operations processed on the associated connection.
   *
   * @return  The total response time in milliseconds for all extended
   *          operations processed on the associated connection.
   */
  public long getTotalExtendedResponseTimeMillis()
  {
    return Math.round(totalExtendedResponseTime.get() / 1_000_000.0d);
  }



  /**
   * Retrieves the average response time in nanoseconds for all extended
   * operations processed on the associated connection.
   *
   * @return  The average response time in nanoseconds for all extended
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no extended operations have yet been
   *          performed.
   */
  public double getAverageExtendedResponseTimeNanos()
  {
    final long totalTime  = totalExtendedResponseTime.get();
    final long totalCount = numExtendedResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the average response time in milliseconds for all extended
   * operations processed on the associated connection.
   *
   * @return  The average response time in milliseconds for all extended
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no extended operations have yet been
   *          performed.
   */
  public double getAverageExtendedResponseTimeMillis()
  {
    final long totalTime  = totalExtendedResponseTime.get();
    final long totalCount = numExtendedResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1_000_000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the number of modify requests sent on the associated connection.
   *
   * @return  The number of modify requests sent on the associated connection.
   */
  public long getNumModifyRequests()
  {
    return numModifyRequests.get();
  }



  /**
   * Increments the number of modify requests sent on the associated connection.
   */
  void incrementNumModifyRequests()
  {
    numModifyRequests.incrementAndGet();
  }



  /**
   * Retrieves the number of modify responses sent on the associated connection.
   *
   * @return  The number of modify responses sent on the associated connection.
   */
  public long getNumModifyResponses()
  {
    return numModifyResponses.get();
  }



  /**
   * Increments the number of modify responses sent on the associated
   * connection.
   *
   * @param  responseTime  The length of time in nanoseconds between sending
   *                       the request and receiving the response.
   */
  void incrementNumModifyResponses(final long responseTime)
  {
    numModifyResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalModifyResponseTime.addAndGet(responseTime);
    }
  }



  /**
   * Retrieves the total response time in nanoseconds for all modify
   * operations processed on the associated connection.
   *
   * @return  The total response time in nanoseconds for all modify operations
   *          processed on the associated connection.
   */
  public long getTotalModifyResponseTimeNanos()
  {
    return totalModifyResponseTime.get();
  }



  /**
   * Retrieves the total response time in milliseconds for all modify
   * operations processed on the associated connection.
   *
   * @return  The total response time in milliseconds for all modify operations
   *          processed on the associated connection.
   */
  public long getTotalModifyResponseTimeMillis()
  {
    return Math.round(totalModifyResponseTime.get() / 1_000_000.0d);
  }



  /**
   * Retrieves the average response time in nanoseconds for all modify
   * operations processed on the associated connection.
   *
   * @return  The average response time in nanoseconds for all modify
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no modify operations have yet been
   *          performed.
   */
  public double getAverageModifyResponseTimeNanos()
  {
    final long totalTime  = totalModifyResponseTime.get();
    final long totalCount = numModifyResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the average response time in milliseconds for all modify
   * operations processed on the associated connection.
   *
   * @return  The average response time in milliseconds for all modify
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no modify operations have yet been
   *          performed.
   */
  public double getAverageModifyResponseTimeMillis()
  {
    final long totalTime  = totalModifyResponseTime.get();
    final long totalCount = numModifyResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1_000_000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the number of modify DN requests sent on the associated
   * connection.
   *
   * @return  The number of modify DN requests sent on the associated
   *          connection.
   */
  public long getNumModifyDNRequests()
  {
    return numModifyDNRequests.get();
  }



  /**
   * Increments the number of modify DN requests sent on the associated
   * connection.
   */
  void incrementNumModifyDNRequests()
  {
    numModifyDNRequests.incrementAndGet();
  }



  /**
   * Retrieves the number of modify DN responses sent on the associated
   * connection.
   *
   * @return  The number of modify DN responses sent on the associated
   *          connection.
   */
  public long getNumModifyDNResponses()
  {
    return numModifyDNResponses.get();
  }



  /**
   * Increments the number of modify DN responses sent on the associated
   * connection.
   *
   * @param  responseTime  The length of time in nanoseconds between sending
   *                       the request and receiving the response.
   */
  void incrementNumModifyDNResponses(final long responseTime)
  {
    numModifyDNResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalModifyDNResponseTime.addAndGet(responseTime);
    }
  }



  /**
   * Retrieves the total response time in nanoseconds for all modify DN
   * operations processed on the associated connection.
   *
   * @return  The total response time in nanoseconds for all modify DN
   *          operations processed on the associated connection.
   */
  public long getTotalModifyDNResponseTimeNanos()
  {
    return totalModifyDNResponseTime.get();
  }



  /**
   * Retrieves the total response time in milliseconds for all modify DN
   * operations processed on the associated connection.
   *
   * @return  The total response time in milliseconds for all modify DN
   *          operations processed on the associated connection.
   */
  public long getTotalModifyDNResponseTimeMillis()
  {
    return Math.round(totalModifyDNResponseTime.get() / 1_000_000.0d);
  }



  /**
   * Retrieves the average response time in nanoseconds for all modify DN
   * operations processed on the associated connection.
   *
   * @return  The average response time in nanoseconds for all modify DN
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no modify DN operations have yet been
   *          performed.
   */
  public double getAverageModifyDNResponseTimeNanos()
  {
    final long totalTime  = totalModifyDNResponseTime.get();
    final long totalCount = numModifyDNResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the average response time in milliseconds for all modify DN
   * operations processed on the associated connection.
   *
   * @return  The average response time in milliseconds for all modify DN
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no modify DN operations have yet been
   *          performed.
   */
  public double getAverageModifyDNResponseTimeMillis()
  {
    final long totalTime  = totalModifyDNResponseTime.get();
    final long totalCount = numModifyDNResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1_000_000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the number of search requests sent on the associated connection.
   *
   * @return  The number of search requests sent on the associated connection.
   */
  public long getNumSearchRequests()
  {
    return numSearchRequests.get();
  }



  /**
   * Increments the number of search requests sent on the associated
   * connection.
   */
  void incrementNumSearchRequests()
  {
    numSearchRequests.incrementAndGet();
  }



  /**
   * Retrieves the number of search result entry responses received on the
   * associated connection.
   *
   * @return  The number of search result entry responses received on the
   *          associated connection.
   */
  public long getNumSearchEntryResponses()
  {
    return numSearchEntryResponses.get();
  }



  /**
   * Retrieves the number of search result reference responses received on the
   * associated connection.
   *
   * @return  The number of search result reference responses received on the
   *          associated connection.
   */
  public long getNumSearchReferenceResponses()
  {
    return numSearchReferenceResponses.get();
  }



  /**
   * Retrieves the number of search result done responses received on the
   * associated connection.
   *
   * @return  The number of search result done responses received on the
   *          associated connection.
   */
  public long getNumSearchDoneResponses()
  {
    return numSearchDoneResponses.get();
  }



  /**
   * Increments the number of search result done responses received on the
   * associated connection.
   *
   * @param  numEntries     The number of search result entries returned for the
   *                        search.
   * @param  numReferences  The number of search result references returned for
   *                        the search.
   * @param  responseTime   The length of time in nanoseconds between sending
   *                        the search request and receiving the search result
   *                        done response.
   */
  void incrementNumSearchResponses(final int numEntries,
                                   final int numReferences,
                                   final long responseTime)
  {
    numSearchEntryResponses.addAndGet(numEntries);
    numSearchReferenceResponses.addAndGet(numReferences);
    numSearchDoneResponses.incrementAndGet();

    if (responseTime > 0)
    {
      totalSearchResponseTime.addAndGet(responseTime);
    }
  }



  /**
   * Retrieves the total response time in nanoseconds for all search
   * operations processed on the associated connection.
   *
   * @return  The total response time in nanoseconds for all search operations
   *          processed on the associated connection.
   */
  public long getTotalSearchResponseTimeNanos()
  {
    return totalSearchResponseTime.get();
  }



  /**
   * Retrieves the total response time in milliseconds for all search
   * operations processed on the associated connection.
   *
   * @return  The total response time in milliseconds for all search operations
   *          processed on the associated connection.
   */
  public long getTotalSearchResponseTimeMillis()
  {
    return Math.round(totalSearchResponseTime.get() / 1_000_000.0d);
  }



  /**
   * Retrieves the average response time in nanoseconds for all search
   * operations processed on the associated connection.
   *
   * @return  The average response time in nanoseconds for all search
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no compare operations have yet been
   *          performed.
   */
  public double getAverageSearchResponseTimeNanos()
  {
    final long totalTime  = totalSearchResponseTime.get();
    final long totalCount = numSearchDoneResponses.get();

    if (totalTime > 0)
    {
      return (1.0d * totalTime / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the average response time in milliseconds for all search
   * operations processed on the associated connection.
   *
   * @return  The average response time in milliseconds for all search
   *          operations processed on the associated connection, or
   *          {@code Double.NaN} if no compare operations have yet been
   *          performed.
   */
  public double getAverageSearchResponseTimeMillis()
  {
    final long totalTime  = totalSearchResponseTime.get();
    final long totalCount = numSearchDoneResponses.get();

    if (totalTime > 0)
    {
      return (totalTime / 1_000_000.0d / totalCount);
    }
    else
    {
      return Double.NaN;
    }
  }



  /**
   * Retrieves the number of unbind requests sent on the associated connection.
   *
   * @return  The number of unbind requests sent on the associated connection.
   */
  public long getNumUnbindRequests()
  {
    return numUnbindRequests.get();
  }



  /**
   * Increments the number of unbind requests sent on the associated
   * connection.
   */
  void incrementNumUnbindRequests()
  {
    numUnbindRequests.incrementAndGet();
  }



  /**
   * Retrieves a string representation of this LDAP connection statistics
   * object.
   *
   * @return  A string representation of this LDAP connection statistics object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this LDAP connection statistics object
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    final long connects          = numConnects.get();
    final long disconnects       = numDisconnects.get();
    final long abandonRequests   = numAbandonRequests.get();
    final long addRequests       = numAddRequests.get();
    final long addResponses      = numAddResponses.get();
    final long addTimes          = totalAddResponseTime.get();
    final long bindRequests      = numBindRequests.get();
    final long bindResponses     = numBindResponses.get();
    final long bindTimes         = totalBindResponseTime.get();
    final long compareRequests   = numCompareRequests.get();
    final long compareResponses  = numCompareResponses.get();
    final long compareTimes      = totalCompareResponseTime.get();
    final long deleteRequests    = numDeleteRequests.get();
    final long deleteResponses   = numDeleteResponses.get();
    final long deleteTimes       = totalDeleteResponseTime.get();
    final long extendedRequests  = numExtendedRequests.get();
    final long extendedResponses = numExtendedResponses.get();
    final long extendedTimes     = totalExtendedResponseTime.get();
    final long modifyRequests    = numModifyRequests.get();
    final long modifyResponses   = numModifyResponses.get();
    final long modifyTimes       = totalModifyResponseTime.get();
    final long modifyDNRequests  = numModifyDNRequests.get();
    final long modifyDNResponses = numModifyDNResponses.get();
    final long modifyDNTimes     = totalModifyDNResponseTime.get();
    final long searchRequests    = numSearchRequests.get();
    final long searchEntries     = numSearchEntryResponses.get();
    final long searchReferences  = numSearchReferenceResponses.get();
    final long searchDone        = numSearchDoneResponses.get();
    final long searchTimes       = totalSearchResponseTime.get();
    final long unbindRequests    = numUnbindRequests.get();

    final DecimalFormat f = new DecimalFormat("0.000");

    buffer.append("LDAPConnectionStatistics(numConnects=");
    buffer.append(connects);
    buffer.append(", numDisconnects=");
    buffer.append(disconnects);

    buffer.append(", numAbandonRequests=");
    buffer.append(abandonRequests);

    buffer.append(", numAddRequests=");
    buffer.append(addRequests);
    buffer.append(", numAddResponses=");
    buffer.append(addResponses);
    buffer.append(", totalAddResponseTimeNanos=");
    buffer.append(addTimes);
    if (addTimes > 0L)
    {
      buffer.append(", averageAddResponseTimeNanos=");
      buffer.append(f.format(1.0d * addResponses / addTimes));
    }

    buffer.append(", numBindRequests=");
    buffer.append(bindRequests);
    buffer.append(", numBindResponses=");
    buffer.append(bindResponses);
    buffer.append(", totalBindResponseTimeNanos=");
    buffer.append(bindTimes);
    if (bindTimes > 0L)
    {
      buffer.append(", averageBindResponseTimeNanos=");
      buffer.append(f.format(1.0d * bindResponses / bindTimes));
    }

    buffer.append(", numCompareRequests=");
    buffer.append(compareRequests);
    buffer.append(", numCompareResponses=");
    buffer.append(compareResponses);
    buffer.append(", totalCompareResponseTimeNanos=");
    buffer.append(compareTimes);
    if (compareTimes > 0L)
    {
      buffer.append(", averageCompareResponseTimeNanos=");
      buffer.append(f.format(1.0d * compareResponses / compareTimes));
    }

    buffer.append(", numDeleteRequests=");
    buffer.append(deleteRequests);
    buffer.append(", numDeleteResponses=");
    buffer.append(deleteResponses);
    buffer.append(", totalDeleteResponseTimeNanos=");
    buffer.append(deleteTimes);
    if (deleteTimes > 0L)
    {
      buffer.append(", averageDeleteResponseTimeNanos=");
      buffer.append(f.format(1.0d * deleteResponses / deleteTimes));
    }

    buffer.append(", numExtendedRequests=");
    buffer.append(extendedRequests);
    buffer.append(", numExtendedResponses=");
    buffer.append(extendedResponses);
    buffer.append(", totalExtendedResponseTimeNanos=");
    buffer.append(extendedTimes);
    if (extendedTimes > 0L)
    {
      buffer.append(", averageExtendedResponseTimeNanos=");
      buffer.append(f.format(1.0d * extendedResponses / extendedTimes));
    }

    buffer.append(", numModifyRequests=");
    buffer.append(modifyRequests);
    buffer.append(", numModifyResponses=");
    buffer.append(modifyResponses);
    buffer.append(", totalModifyResponseTimeNanos=");
    buffer.append(modifyTimes);
    if (modifyTimes > 0L)
    {
      buffer.append(", averageModifyResponseTimeNanos=");
      buffer.append(f.format(1.0d * modifyResponses / modifyTimes));
    }

    buffer.append(", numModifyDNRequests=");
    buffer.append(modifyDNRequests);
    buffer.append(", numModifyDNResponses=");
    buffer.append(modifyDNResponses);
    buffer.append(", totalModifyDNResponseTimeNanos=");
    buffer.append(modifyDNTimes);
    if (modifyDNTimes > 0L)
    {
      buffer.append(", averageModifyDNResponseTimeNanos=");
      buffer.append(f.format(1.0d * modifyDNResponses / modifyDNTimes));
    }

    buffer.append(", numSearchRequests=");
    buffer.append(searchRequests);
    buffer.append(", numSearchEntries=");
    buffer.append(searchEntries);
    buffer.append(", numSearchReferences=");
    buffer.append(searchReferences);
    buffer.append(", numSearchDone=");
    buffer.append(searchDone);
    buffer.append(", totalSearchResponseTimeNanos=");
    buffer.append(searchTimes);
    if (searchTimes > 0L)
    {
      buffer.append(", averageSearchResponseTimeNanos=");
      buffer.append(f.format(1.0d * searchDone / searchTimes));
    }

    buffer.append(", numUnbindRequests=");
    buffer.append(unbindRequests);

    buffer.append(')');
  }
}
