/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;



/**
 * This class defines a background thread that will be used to periodically
 * check the health of available connections in a connection pool.
 */
class LDAPConnectionPoolHealthCheckThread
      extends Thread
{
  // Indicates whether a request has been made to shut down this health check
  // thread.
  @NotNull private final AtomicBoolean stopRequested;

  // The connection pool with which this thread is associated.
  @NotNull private final AbstractConnectionPool pool;

  // A blocking queue used to control sleeping between checks and to wait for a
  // shutdown signal.
  @NotNull private final LinkedBlockingQueue<Object> queue;

  // A reference to the thread used to perform the periodic health checks.
  @Nullable private volatile Thread thread;



  /**
   * Creates a new instance of this health check thread that will be used to
   * examine connections in the provided pool.
   *
   * @param  pool  The connection pool with which this thread will be
   *               associated.
   */
  LDAPConnectionPoolHealthCheckThread(
       @NotNull final AbstractConnectionPool pool)
  {
    setName("Health Check Thread for " + pool.toString());
    setDaemon(true);

    this.pool = pool;

    stopRequested = new AtomicBoolean(false);
    queue = new LinkedBlockingQueue<>(1);
    thread = null;
  }



  /**
   * Periodically tests the health of available connections in the pool.
   */
  @Override()
  public void run()
  {
    thread = Thread.currentThread();
    long lastCheckTime = System.currentTimeMillis();

    while (! stopRequested.get())
    {
      final long timeSinceLastCheck =
           System.currentTimeMillis() - lastCheckTime;
      if (timeSinceLastCheck >= pool.getHealthCheckIntervalMillis())
      {
        try
        {
          pool.doHealthCheck();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }

        try
        {
          pool.getHealthCheck().performPoolMaintenance(pool);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }

        lastCheckTime = System.currentTimeMillis();
      }
      else
      {
        final long sleepTime = Math.min(
             (pool.getHealthCheckIntervalMillis() - timeSinceLastCheck),
             30_000L);
        try
        {
          queue.poll(sleepTime, TimeUnit.MILLISECONDS);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    thread = null;
  }



  /**
   * Indicates that this health check thread should stop running.
   *
   * @param  wait  Indicates whether to wait for the thread to actually stop
   *               running before returning.  If this is {@code true}, then this
   *               method will not return until the thread has actually stopped.
   *               If this is {@code false}, then the thread will be signaled
   *               to stop, but the thread may still be running when this method
   *               returns.
   */
  void stopRunning(final boolean wait)
  {
    stopRequested.set(true);
    wakeUp();

    if (wait)
    {
      final Thread t = thread;
      if (t != null)
      {
        try
        {
          t.join();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);

          if (e instanceof InterruptedException)
          {
            Thread.currentThread().interrupt();
          }
        }
      }
    }
  }



  /**
   * Indicates that this health check thread should wake up if it is currently
   * sleeping and check to see if the pool configuration has changed or if a
   * shutdown request has been received.
   */
  void wakeUp()
  {
    queue.offer(new Object());
  }
}
