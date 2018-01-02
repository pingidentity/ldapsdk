/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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

import static com.unboundid.util.Debug.*;



/**
 * This class defines a background thread that will be used to periodically
 * check the health of available connections in a connection pool.
 */
class LDAPConnectionPoolHealthCheckThread
      extends Thread
{
  // Indicates whether a request has been made to shut down this health check
  // thread.
  private final AtomicBoolean stopRequested;

  // The connection pool with which this thread is associated.
  private final AbstractConnectionPool pool;

  // A blocking queue used to control sleeping between checks and to wait for a
  // shutdown signal.
  private final LinkedBlockingQueue<Object> queue;

  // A reference to the thread used to perform the periodic health checks.
  private volatile Thread thread;



  /**
   * Creates a new instance of this health check thread that will be used to
   * examine connections in the provided pool.
   *
   * @param  pool  The connection pool with which this thread will be
   *               associated.
   */
  LDAPConnectionPoolHealthCheckThread(final AbstractConnectionPool pool)
  {
    setName("Health Check Thread for " + pool.toString());
    setDaemon(true);

    this.pool = pool;

    stopRequested = new AtomicBoolean(false);
    queue = new LinkedBlockingQueue<Object>(1);
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
          debugException(e);
        }
        lastCheckTime = System.currentTimeMillis();
      }
      else
      {
        final long sleepTime = Math.min(
             (pool.getHealthCheckIntervalMillis() - timeSinceLastCheck),
             30000L);
        try
        {
          queue.poll(sleepTime, TimeUnit.MILLISECONDS);
        }
        catch (final Exception e)
        {
          debugException(e);
        }
      }
    }

    thread = null;
  }



  /**
   * Indicates that this health check thread should stop running.  This method
   * will not return until the thread has stopped running.
   */
  void stopRunning()
  {
    stopRequested.set(true);
    wakeUp();

    final Thread t = thread;
    if (t != null)
    {
      try
      {
        t.join();
      }
      catch (final Exception e)
      {
        debugException(e);

        if (e instanceof InterruptedException)
        {
          Thread.currentThread().interrupt();
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
