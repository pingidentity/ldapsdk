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
import java.util.Collection;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;



/**
 * This class provides a parallel mechanism for concurrently closing a set of
 * connections in a connection pool.
 */
final class ParallelPoolCloser
{
  // Indicates whether to try to send an unbind request to the server before
  // closing the connection.
  private final boolean unbind;

  // A collection containing the connections to be closed.
  @NotNull private final Collection<LDAPConnection> connections;

  // The number of threads to use to establish connections in parallel.
  private final int numThreads;



  /**
   * Creates a new parallel pool closer with the provided settings.
   *
   * @param  connections  A collection containing the connections to be closed.
   *                      No items will be added to or removed from the
   *                      collection in the course of processing.
   * @param  unbind       Indicates whether to try to send an unbind request to
   *                      the server before closing the connection.
   * @param  numThreads   The number of threads to use to close the connections
   *                      in parallel.
   */
  ParallelPoolCloser(@NotNull final Collection<LDAPConnection> connections,
                     final boolean unbind, final int numThreads)
  {
    this.connections = connections;
    this.unbind      = unbind;
    this.numThreads  = numThreads;
  }



  /**
   * Performs the work of closing the connections.  This method will not return
   * until all connections have been closed.
   */
  void closeConnections()
  {
    final int numConnections = connections.size();

    final ArrayBlockingQueue<Runnable> queue =
         new ArrayBlockingQueue<>(numConnections);
    final ThreadPoolExecutor executor = new ThreadPoolExecutor(numThreads,
         numThreads, 0L, TimeUnit.MILLISECONDS, queue);

    final ArrayList<Future<?>> results = new ArrayList<>(numConnections);
    for (final LDAPConnection conn : connections)
    {
      results.add(executor.submit(new ParallelPoolCloserTask(conn, unbind)));
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
  }
}
