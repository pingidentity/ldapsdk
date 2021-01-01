/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;



/**
 * This class provides a parallel mechanism for concurrently establishing the
 * initial set of connections for inclusion in a connection pool.
 */
final class ParallelPoolConnector
{
  // Indicates whether to throw an exception if a problem is encountered while
  // attempting to establish the connections.
  private final boolean throwOnConnectFailure;

  // The number of connections to establish.
  private final int numConnections;

  // The number of threads to use to establish connections in parallel.
  private final int numThreads;

  // The connection pool with which the connections will be associated.
  @NotNull private final LDAPConnectionPool pool;

  // The list that will hold the connections that are established.  It must be
  // threadsafe.
  @NotNull private final List<LDAPConnection> connList;



  /**
   * Creates a new parallel pool connector with the provided settings.
   *
   * @param  pool                   The connection pool with which the
   *                                connections will be associated.
   * @param  connList               The list that will hold the connections that
   *                                are established.  It must be threadsafe.
   * @param  numConnections         The number of connections to be established.
   * @param  numThreads             The number of threads to use to establish
   *                                connections in parallel.
   * @param  throwOnConnectFailure  If an exception should be thrown if a
   *                                problem is encountered while attempting to
   *                                create the specified initial number of
   *                                connections.  If {@code true}, then the
   *                                attempt to create the pool will fail.if any
   *                                connection cannot be established.  If
   *                                {@code false}, then the pool will be created
   *                                but may have fewer than the initial number
   *                                of connections (or possibly no connections).
   */
  ParallelPoolConnector(@NotNull final LDAPConnectionPool pool,
                        @NotNull final List<LDAPConnection> connList,
                        final int numConnections,
                        final int numThreads,
                        final boolean throwOnConnectFailure)
  {
    this.pool                  = pool;
    this.connList              = connList;
    this.numConnections        = numConnections;
    this.numThreads            = numThreads;
    this.throwOnConnectFailure = throwOnConnectFailure;
  }



  /**
   * Performs the work of establishing the connections.  This method will not
   * return until all connections have been established or an exception is
   * encountered.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         establish any of the connections and
   *                         {@code throwOnConnectFailure} is {@code true}.
   */
  void establishConnections()
       throws LDAPException
  {
    final ArrayBlockingQueue<Runnable> queue =
         new ArrayBlockingQueue<>(numConnections);
    final ThreadPoolExecutor executor = new ThreadPoolExecutor(numThreads,
         numThreads, 0L, TimeUnit.MILLISECONDS, queue);

    final AtomicReference<LDAPException> firstException =
         new AtomicReference<>();

    final ArrayList<Future<?>> results = new ArrayList<>(numConnections);
    for (int i=0; i < numConnections; i++)
    {
      results.add(executor.submit(new ParallelPoolConnectorTask(pool, connList,
           firstException, throwOnConnectFailure)));
    }

    for (final Future<?> f : results)
    {
      try
      {
        f.get();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    executor.shutdown();

    if (throwOnConnectFailure)
    {
      final LDAPException le = firstException.get();
      if (le != null)
      {
        for (final LDAPConnection c : connList)
        {
          c.terminate(null);
        }
        connList.clear();
        throw le;
      }
    }
  }
}
