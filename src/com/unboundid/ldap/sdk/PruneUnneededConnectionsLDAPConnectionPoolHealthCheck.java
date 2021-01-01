/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;

import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an LDAP connection pool health check
 * that periodically monitors the number of available connections in the pool.
 * If the number of available connections has been consistently greater than a
 * specified minimum for at least a given length of time, then the number of
 * available connections will be reduced to that minimum.  Note that the
 * size of the pool will only be checked at interval's specified by the
 * {@link AbstractConnectionPool#getHealthCheckIntervalMillis()} method, so it
 * is possible that the number of available connections may have dipped below
 * that minimum on one or more occasions between checks.  Also note that this
 * health check can only be used on instances of the
 * {@link LDAPConnectionPool} class; it cannot be used with
 * {@link LDAPThreadLocalConnectionPool} instances.
 */
@ThreadSafety(level= ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PruneUnneededConnectionsLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
{
  // A reference to the first time at which the number of available connections
  // exceeded the minimum number of available connections.  It may reference a
  // null value if the last check indicated that the number of available
  // connections was not larger than the configured minimum.
  @NotNull private final AtomicReference<Long>
                     earliestTimeWithMoreThanMinAvailableConnections;

  // The minimum number of connections that should be maintained in the
  // connection pool.  This health check will only remove connections if the
  // pool has more than this number of connections for at least the specified
  // duration.
  private final int minAvailableConnections;

  // The minimum length of time in milliseconds that the pool should have had
  // at least the specified minimum number of available connections before any
  // connections may be removed.
  private final long minDurationMillisExceedingMinAvailableConnections;



  /**
   * Creates a new instance of this LDAP connection pool health check with the
   * provided information.
   *
   * @param  minAvailableConnections
   *              The minimum number of connections that should be maintained in
   *              the connection pool.  This health check will only remove
   *              connections if the pool has more than this number of
   *              connections for at least the specified duration.  A value that
   *              is less than or equal to zero indicates that no minimum number
   *              of connections needs to be maintained.
   * @param  minDurationMillisExceedingMinAvailableConnections
   *              The minimum length of time in milliseconds that the pool
   *              should have reported at least the specified minimum number of
   *              available connections before any connections may be removed.
   *              Note that the number of connections will only be checked at
   *              intervals specified by the
   *              {@link AbstractConnectionPool#getHealthCheckIntervalMillis()}
   *              method, so it may be possible for the number of available
   *              connections to dip below this value one or more time between
   *              intervals and still cause the pool to be reduced in size.  A
   *              value that is less than or equal to zero indicates that the
   *              pool size should be reduced to the configured minimum any time
   *              there are more than that number of connections available.
   */
  public PruneUnneededConnectionsLDAPConnectionPoolHealthCheck(
              final int minAvailableConnections,
              final long minDurationMillisExceedingMinAvailableConnections)
  {
    this.minAvailableConnections = Math.max(0, minAvailableConnections);
    this.minDurationMillisExceedingMinAvailableConnections = Math.max(0L,
         minDurationMillisExceedingMinAvailableConnections);

    earliestTimeWithMoreThanMinAvailableConnections = new AtomicReference<>();
  }



  /**
   * Retrieves the minimum number of connections that should be maintained in
   * the connection pool.  This health check will only remove connections if the
   * pool has more than this number of connections for at least the specified
   * duration.
   *
   * @return  The minimum number of connections that should be maintained in the
   *          connection pool.
   */
  public int getMinAvailableConnections()
  {
    return minAvailableConnections;
  }



  /**
   * Retrieves the minimum length of time in milliseconds that the pool should
   * have reported at least the specified minimum number of available
   * connections before any connections may be removed.  Note that the number of
   * connections will only be checked at intervals specified by the
   * {@link AbstractConnectionPool#getHealthCheckIntervalMillis()} method, so it
   * may be possible for the number of available connections to dip below this
   * value one or more time between intervals and still cause the pool to be
   * reduced in size.
   *
   * @return  The minimum length of time in milliseconds that the pool should
   *          have reported at least the specified minimum number of available
   *          connections before any connections may be removed.
   */
  public long getMinDurationMillisExceedingMinAvailableConnections()
  {
    return minDurationMillisExceedingMinAvailableConnections;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void performPoolMaintenance(@NotNull final AbstractConnectionPool pool)
  {
    if (! (pool instanceof LDAPConnectionPool))
    {
      Debug.debug(Level.WARNING, DebugType.CONNECT,
             "Only " + LDAPConnectionPool.class.getName() +
                  " instances may be used in conjunction with the " +
                  "PruneUnneededConnectionsLDAPConnectionPoolHealthCheck.  " +
                  "The provided pool had an incompatible type of " +
                  pool.getClass().getName() + '.');

      earliestTimeWithMoreThanMinAvailableConnections.set(null);
      return;
    }

    final int availableConnections = pool.getCurrentAvailableConnections();
    if (availableConnections <= minAvailableConnections)
    {
      earliestTimeWithMoreThanMinAvailableConnections.set(null);
      return;
    }

    final Long earliestTime =
         earliestTimeWithMoreThanMinAvailableConnections.get();
    if (earliestTime == null)
    {
      if (minDurationMillisExceedingMinAvailableConnections <= 0L)
      {
        ((LDAPConnectionPool) pool).shrinkPool(minAvailableConnections);
      }
      else
      {
        earliestTimeWithMoreThanMinAvailableConnections.set(
             System.currentTimeMillis());
      }
    }
    else
    {
      final long millisWithMoreThanMinAvailableConnections =
           System.currentTimeMillis() - earliestTime;
      if (millisWithMoreThanMinAvailableConnections >=
           minDurationMillisExceedingMinAvailableConnections)
      {
        ((LDAPConnectionPool) pool).shrinkPool(minAvailableConnections);
        earliestTimeWithMoreThanMinAvailableConnections.set(null);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PruneUnneededConnectionsLDAPConnectionPoolHealthCheck(" +
         "minAvailableConnections=");
    buffer.append(minAvailableConnections);
    buffer.append(", minDurationMillisExceedingMinAvailableConnections=");
    buffer.append(minDurationMillisExceedingMinAvailableConnections);
    buffer.append(')');
  }
}
