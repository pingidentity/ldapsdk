/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import java.util.Iterator;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a mechanism to ensure that a blocked attempt to write to
 * a socket respects the request timeout and does not block indefinitely.  Java
 * does not provide this capability for regular socket I/O (SO_TIMEOUT only
 * applies to reads and has no effect for writes), so the only way to interrupt
 * a blocked socket write attempt is to close the socket.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class WriteTimeoutHandler
      extends TimerTask
{
  /**
   * The timer that will be used to identify and close connections on which
   * write attempts have been blocked for too long.
   */
  @NotNull private static final AtomicReference<ObjectPair<Timer,AtomicLong>>
       TIMER_REFERENCE = new AtomicReference<>();



  /**
   * The interval, in milliseconds, at which the timer should examine
   * connections to determine whether to close of them because of a blocked
   * write.
   */
  private static final long TIMER_INTERVAL_MILLIS = 100L;



  // Indicates whether this instance has been destroyed.
  @NotNull private final AtomicBoolean destroyed;

  // A counter used to keep track of the number of connections using the
  // associated timer.
  @NotNull private final AtomicLong connectionsUsingTimer;

  // A counter that will be used to create a unique identifier for each write.
  @NotNull private final AtomicLong counter;

  // A map that associates a unique identifier for each write with the timeout
  // for that write.
  @NotNull private final ConcurrentHashMap<Long,Long> writeTimeouts;

  // A handle to the connection with which this handler is associated.
  @NotNull private final LDAPConnection connection;

  // The timer with which this task is associated.
  @NotNull private final Timer timer;



  /**
   * Creates a new write timeout handler for the provided connection.
   *
   * @param  connection  The connection with which this write timeout handler is
   *                     associated.
   */
  WriteTimeoutHandler(@NotNull final LDAPConnection connection)
  {
    this.connection = connection;

    destroyed = new AtomicBoolean(false);
    counter = new AtomicLong(0L);
    writeTimeouts = new ConcurrentHashMap<>(10);

    synchronized (TIMER_REFERENCE)
    {
      final ObjectPair<Timer,AtomicLong> timerPair = TIMER_REFERENCE.get();
      if (timerPair == null)
      {
        timer = new Timer("Write Timeout Handler Timer", true);
        connectionsUsingTimer = new AtomicLong(1L);
        TIMER_REFERENCE.set(new ObjectPair<>(timer, connectionsUsingTimer));
      }
      else
      {
        timer = timerPair.getFirst();
        connectionsUsingTimer = timerPair.getSecond();
        connectionsUsingTimer.incrementAndGet();
      }

      timer.schedule(this, TIMER_INTERVAL_MILLIS, TIMER_INTERVAL_MILLIS);
    }
  }



  /**
   * Examines all entries in the map to see if any of them indicate that a write
   * attempt has been blocked for longer than the maximum acceptable length of
   * time.  If so, then the connection will be closed.
   */
  @Override()
  public void run()
  {
    final long currentTime = System.currentTimeMillis();

    final Iterator<Map.Entry<Long,Long>> iterator =
         writeTimeouts.entrySet().iterator();
    while (iterator.hasNext())
    {
      final long closeTime = iterator.next().getValue();
      if (currentTime > closeTime)
      {
        try
        {
          connection.getConnectionInternals(true).getSocket().close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return;
        }
      }
    }
  }



  /**
   * Cancels this timer task so that it will no longer be active for this
   * connection.
   *
   * @return  {@code true} if the task was successfully cancelled, or
   *          {@code false} if it could not be cancelled for some reason (for
   *          example, because it has already been canceled).
   */
  @Override()
  public boolean cancel()
  {
    final boolean result = super.cancel();
    timer.purge();
    return result;
  }



  /**
   * Destroys this timer task (by canceling it) when a connection is closed.
   * If no more connections are using the timer, then the timer itself will be
   * canceled (to shut down its associated thread background).
   */
  void destroy()
  {
    cancel();

    if (destroyed.getAndSet(true))
    {
      // This instance has already been destroyed.  Don't do it again.
      return;
    }

    synchronized (TIMER_REFERENCE)
    {
      final long remainingConnectionsUsingTimer =
           connectionsUsingTimer.decrementAndGet();
      if (remainingConnectionsUsingTimer <= 0L)
      {
        TIMER_REFERENCE.set(null);
        timer.cancel();
      }
    }
  }



  /**
   * Indicates that the connection is going to attempt to write data, and that
   * the connection should be closed if the {@link #writeCompleted(long)} method
   * is not called within the specified timeout period.
   *
   * @param  timeoutMillis  The maximum length of time, in milliseconds, that
   *                        the write attempt should be allowed to block.  If
   *                        the caller does not indicate that the write has
   *                        completed after this length of time, then the
   *                        connection will be closed.
   *
   * @return  A unique identifier that has been assigned to the write operation.
   *          When the write completes, the {@link #writeCompleted(long)} method
   *          must be called with this value as the argument.
   */
  long beginWrite(final long timeoutMillis)
  {
    final long id = counter.getAndIncrement();
    final long writeExpirationTime = System.currentTimeMillis() + timeoutMillis;
    writeTimeouts.put(id, writeExpirationTime);
    return id;
  }



  /**
   * Indicates that the specified write has completed.
   *
   * @param  writeID  The
   */
  void writeCompleted(final long writeID)
  {
    writeTimeouts.remove(writeID);
  }
}
