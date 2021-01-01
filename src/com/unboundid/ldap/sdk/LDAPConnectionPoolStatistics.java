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
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure with information about usage of an LDAP
 * connection pool.  Calls to update statistics maintained by this class are
 * threadsafe, but attempts to access different statistics may not be consistent
 * if operations may be in progress in the connection pool.
 * <BR><BR>
 * The set of statistics maintained for connection pools include:
 * <UL>
 *   <LI>The current number of connections that are available within the
 *       pool.</LI>
 *   <LI>The maximum number of connections that may be available within the
 *       pool.</LI>
 *   <LI>The total number of connections that have been successfully checked out
 *       of the pool.</LI>
 *   <LI>The number of connections that have been successfully checked out of
 *       of the pool without needing to wait for a connection to become
 *       available.
 *   <LI>The number of connections that have been successfully checked out of
 *       the pool after waiting for a connection to become available.</LI>
 *   <LI>The number of connections that have been successfully checked out of
 *       the pool after creating a new connection to service the request.</LI>
 *   <LI>The number of failed attempts to check a connection out of the
 *       pool.</LI>
 *   <LI>The number of connections that have been released back to the pool as
 *       valid.</LI>
 *   <LI>The number of connections that have been closed as defunct.</LI>
 *   <LI>The number of connections that have been closed as expired (i.e., that
 *       had been established for the maximum connection age).</LI>
 *   <LI>The number of connections that have been closed as unneeded (because
 *       the pool already had the maximum number of available connections).</LI>
 *   <LI>The number of successful attempts to create a new connection for use in
 *       the pool.</LI>
 *   <LI>The number of failed attempts to create a new connection for use in the
 *       pool.</LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
public final class LDAPConnectionPoolStatistics
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1493039391352814874L;



  // The number of connections that have been closed as defunct.
  @NotNull private final AtomicLong numConnectionsClosedDefunct;

  // The number of connections that have been closed because they were expired.
  @NotNull private final AtomicLong numConnectionsClosedExpired;

  // The number of connections that have been closed because they were no longer
  // needed.
  @NotNull private final AtomicLong numConnectionsClosedUnneeded;

  // The number of failed attempts to check out a connection from the pool.
  @NotNull private final AtomicLong numFailedCheckouts;

  // The number of failed attempts to create a connection for use in the pool.
  @NotNull private final AtomicLong numFailedConnectionAttempts;

  // The number of valid connections released back to the pool.
  @NotNull private final AtomicLong numReleasedValid;

  // The number of successful attempts to check out a connection from the pool.
  @NotNull private final AtomicLong numSuccessfulCheckouts;

  // The number of successful checkout attempts that retrieved a connection from
  // the pool after waiting for it to become available.
  @NotNull private final AtomicLong numSuccessfulCheckoutsAfterWait;

  // The number of successful checkout attempts that had to create a new
  // connection because none were available.
  @NotNull private final AtomicLong numSuccessfulCheckoutsNewConnection;

  // The number of successful checkout attempts that were able to take an
  // existing connection without waiting.
  @NotNull private final AtomicLong numSuccessfulCheckoutsWithoutWait;

  // The number successful attempts to create a connection for use in the pool.
  @NotNull private final AtomicLong numSuccessfulConnectionAttempts;

  // The connection pool with which these statistics are associated.
  @NotNull private final AbstractConnectionPool pool;



  /**
   * Creates a new instance of this LDAP connection pool statistics object.  All
   * of the counts will be initialized to zero.
   *
   * @param  pool  The connection pool with which these statistics are
   *               associated.
   */
  public LDAPConnectionPoolStatistics(
              @NotNull final AbstractConnectionPool pool)
  {
    this.pool = pool;

    numSuccessfulConnectionAttempts     = new AtomicLong(0L);
    numFailedConnectionAttempts         = new AtomicLong(0L);
    numConnectionsClosedDefunct         = new AtomicLong(0L);
    numConnectionsClosedExpired         = new AtomicLong(0L);
    numConnectionsClosedUnneeded        = new AtomicLong(0L);
    numSuccessfulCheckouts              = new AtomicLong(0L);
    numSuccessfulCheckoutsAfterWait     = new AtomicLong(0L);
    numSuccessfulCheckoutsNewConnection = new AtomicLong(0L);
    numSuccessfulCheckoutsWithoutWait   = new AtomicLong(0L);
    numFailedCheckouts                  = new AtomicLong(0L);
    numReleasedValid                    = new AtomicLong(0L);
  }



  /**
   * Resets all counters back to zero.
   */
  public void reset()
  {
    numSuccessfulConnectionAttempts.set(0L);
    numFailedConnectionAttempts.set(0L);
    numConnectionsClosedDefunct.set(0L);
    numConnectionsClosedExpired.set(0L);
    numConnectionsClosedUnneeded.set(0L);
    numSuccessfulCheckouts.set(0L);
    numSuccessfulCheckoutsAfterWait.set(0L);
    numSuccessfulCheckoutsNewConnection.set(0L);
    numSuccessfulCheckoutsWithoutWait.set(0L);
    numFailedCheckouts.set(0L);
    numReleasedValid.set(0L);
  }



  /**
   * Retrieves the number of connections that have been successfully created for
   * use in conjunction with the connection pool.
   *
   * @return  The number of connections that have been created for use in
   *          conjunction with the connection pool.
   */
  public long getNumSuccessfulConnectionAttempts()
  {
    return numSuccessfulConnectionAttempts.get();
  }



  /**
   * Increments the number of connections that have been successfully created
   * for use in conjunction with the connection pool.
   */
  void incrementNumSuccessfulConnectionAttempts()
  {
    numSuccessfulConnectionAttempts.incrementAndGet();
  }



  /**
   * Retrieves the number of failed attempts to create a connection for use in
   * the connection pool.
   *
   * @return  The number of failed attempts to create a connection for use in
   *          the connection pool.
   */
  public long getNumFailedConnectionAttempts()
  {
    return numFailedConnectionAttempts.get();
  }



  /**
   * Increments the number of failed attempts to create a connection for use in
   * the connection pool.
   */
  void incrementNumFailedConnectionAttempts()
  {
    numFailedConnectionAttempts.incrementAndGet();
  }



  /**
   * Retrieves the number of connections that have been closed as defunct (i.e.,
   * they are no longer believed to be valid).
   *
   * @return  The number of connections that have been closed as defunct.
   */
  public long getNumConnectionsClosedDefunct()
  {
    return numConnectionsClosedDefunct.get();
  }



  /**
   * Increments the number of connections that have been closed as defunct.
   */
  void incrementNumConnectionsClosedDefunct()
  {
    numConnectionsClosedDefunct.incrementAndGet();
  }



  /**
   * Retrieves the number of connections that have been closed as expired (i.e.,
   * they have been established for longer than the maximum connection age for
   * the pool).
   *
   * @return  The number of connections that have been closed as expired.
   */
  public long getNumConnectionsClosedExpired()
  {
    return numConnectionsClosedExpired.get();
  }



  /**
   * Increments the number of connections that have been closed as expired.
   */
  void incrementNumConnectionsClosedExpired()
  {
    numConnectionsClosedExpired.incrementAndGet();
  }



  /**
   * Retrieves the number of connections that have been closed as unneeded
   * (i.e., they were created in response to heavy load but are no longer needed
   * to meet the current load, or they were closed when the pool was closed).
   *
   * @return  The number of connections that have been closed as unneeded.
   */
  public long getNumConnectionsClosedUnneeded()
  {
    return numConnectionsClosedUnneeded.get();
  }



  /**
   * Increments the number of connections that have been closed as unneeded.
   */
  void incrementNumConnectionsClosedUnneeded()
  {
    numConnectionsClosedUnneeded.incrementAndGet();
  }



  /**
   * Retrieves the number of successful attempts to check out a connection from
   * the pool (including connections checked out for internal use by operations
   * processed as part of the pool).
   *
   * @return  The number of successful attempts to check out a connection from
   *          the pool.
   */
  public long getNumSuccessfulCheckouts()
  {
    return numSuccessfulCheckouts.get();
  }



  /**
   * Retrieves the number of successful attempts to check out a connection from
   * the pool that were able to obtain an existing connection without waiting.
   *
   * @return  The number of successful attempts to check out a connection from
   *          the pool that were able to obtain an existing connection without
   *          waiting.
   */
  public long getNumSuccessfulCheckoutsWithoutWaiting()
  {
    return numSuccessfulCheckoutsWithoutWait.get();
  }



  /**
   * Retrieves the number of successful attempts to check out a connection from
   * the pool that had to wait for a connection to become available.
   *
   * @return  The number of successful attempts to check out a connection from
   *          the pool that had to wait for a connection to become available.
   */
  public long getNumSuccessfulCheckoutsAfterWaiting()
  {
    return numSuccessfulCheckoutsAfterWait.get();
  }



  /**
   * Retrieves the number of successful attempts to check out a connection from
   * the pool that had to create a new connection because no existing
   * connections were available.
   *
   * @return  The number of successful attempts to check out a connection from
   *          the pool that had to create a new connection because no existing
   *          connections were available.
   */
  public long getNumSuccessfulCheckoutsNewConnection()
  {
    return numSuccessfulCheckoutsNewConnection.get();
  }



  /**
   * Increments the number of successful attempts to check out a connection from
   * the pool without waiting.
   */
  void incrementNumSuccessfulCheckoutsWithoutWaiting()
  {
   numSuccessfulCheckouts.incrementAndGet();
   numSuccessfulCheckoutsWithoutWait.incrementAndGet();
  }



  /**
   * Increments the number of successful attempts to check out a connection from
   * the pool after waiting.
   */
  void incrementNumSuccessfulCheckoutsAfterWaiting()
  {
   numSuccessfulCheckouts.incrementAndGet();
   numSuccessfulCheckoutsAfterWait.incrementAndGet();
  }



  /**
   * Increments the number of successful attempts to check out a connection from
   * the pool after creating a new connection.
   */
  void incrementNumSuccessfulCheckoutsNewConnection()
  {
   numSuccessfulCheckouts.incrementAndGet();
   numSuccessfulCheckoutsNewConnection.incrementAndGet();
  }



  /**
   * Retrieves the number of failed attempts to check out a connection from
   * the pool (including connections checked out for internal use by operations
   * processed as part of the pool).
   *
   * @return  The number of failed attempts to check out a connection from
   *          the pool.
   */
  public long getNumFailedCheckouts()
  {
    return numFailedCheckouts.get();
  }



  /**
   * Increments the number of failed attempts to check out a connection from
   * the pool.
   */
  void incrementNumFailedCheckouts()
  {
   numFailedCheckouts.incrementAndGet();
  }



  /**
   * Retrieves the number of times a valid, usable connection has been released
   * back to the pool after being checked out (including connections checked out
   * for internal use by operations processed within the pool).
   *
   * @return  The number of times a valid connection has been released back to
   *          the pool.
   */
  public long getNumReleasedValid()
  {
    return numReleasedValid.get();
  }



  /**
   * Increments the number of times a valid, usable connection has been released
   * back to the pool.
   */
  void incrementNumReleasedValid()
  {
   numReleasedValid.incrementAndGet();
  }



  /**
   * Retrieves the number of connections currently available for use in the
   * pool, if that information is available.
   *
   * @return  The number of connections currently available for use in the pool,
   *          or -1 if that is not applicable for the associated connection pool
   *          implementation.
   */
  public int getNumAvailableConnections()
  {
    return pool.getCurrentAvailableConnections();
  }



  /**
   * Retrieves the maximum number of connections that may be available in the
   * pool at any time, if that information is available.
   *
   * @return  The maximum number of connections that may be available in the
   *          pool at any time, or -1 if that is not applicable for the
   *          associated connection pool implementation.
   */
  public int getMaximumAvailableConnections()
  {
    return pool.getMaximumAvailableConnections();
  }



  /**
   * Retrieves a string representation of this LDAP connection pool statistics
   * object.
   *
   * @return  A string representation of this LDAP connection pool statistics
   *          object.
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
   * Appends a string representation of this LDAP connection pool statistics
   * object to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    final long availableConns      = pool.getCurrentAvailableConnections();
    final long maxConns            = pool.getMaximumAvailableConnections();
    final long successfulConns     = numSuccessfulConnectionAttempts.get();
    final long failedConns         = numFailedConnectionAttempts.get();
    final long connsClosedDefunct  = numConnectionsClosedDefunct.get();
    final long connsClosedExpired  = numConnectionsClosedExpired.get();
    final long connsClosedUnneeded = numConnectionsClosedUnneeded.get();
    final long successfulCheckouts = numSuccessfulCheckouts.get();
    final long failedCheckouts     = numFailedCheckouts.get();
    final long releasedValid       = numReleasedValid.get();

    buffer.append("LDAPConnectionPoolStatistics(numAvailableConnections=");
    buffer.append(availableConns);
    buffer.append(", maxAvailableConnections=");
    buffer.append(maxConns);
    buffer.append(", numSuccessfulConnectionAttempts=");
    buffer.append(successfulConns);
    buffer.append(", numFailedConnectionAttempts=");
    buffer.append(failedConns);
    buffer.append(", numConnectionsClosedDefunct=");
    buffer.append(connsClosedDefunct);
    buffer.append(", numConnectionsClosedExpired=");
    buffer.append(connsClosedExpired);
    buffer.append(", numConnectionsClosedUnneeded=");
    buffer.append(connsClosedUnneeded);
    buffer.append(", numSuccessfulCheckouts=");
    buffer.append(successfulCheckouts);
    buffer.append(", numFailedCheckouts=");
    buffer.append(failedCheckouts);
    buffer.append(", numReleasedValid=");
    buffer.append(releasedValid);
    buffer.append(')');
  }
}
