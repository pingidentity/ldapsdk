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
package com.unboundid.util;



import java.io.Serializable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;



/**
 * This class provides a utility that can be used to sleep for a specified
 * period of time in a manner that allows it to be woken up if necessary.  A
 * single instance of this class may only be used to allow one thread to sleep
 * at any given time, so if multiple threads need to sleep at the same time then
 * a separate {@code WakeableSleeper} instance should be used for each.
 */
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_NOT_THREADSAFE)
public final class WakeableSleeper
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 755656862953269760L;



  // A flag used to prevent multiple concurrent attempts to sleep.
  @NotNull private final AtomicBoolean sleeping;

  // A flag used to indicate that this WakeableSleeper has been shut down.
  @NotNull private final AtomicBoolean shutDown;

  // The number of attempts to wake up this sleeper.
  @NotNull private final AtomicLong wakeupCount;



  /**
   * Creates a new instance of this wakeable sleeper.
   */
  public WakeableSleeper()
  {
    sleeping    = new AtomicBoolean(false);
    shutDown    = new AtomicBoolean(false);
    wakeupCount = new AtomicLong(0L);
  }



  /**
   * Return {@code true} if this {@code WakeableSleeper} instance has been
   * shutdown via the {@code shutDown()} method and {@code false} otherwise.
   *
   * @return  {@code true} if this {@code WakeableSleeper} instance has been
   *          shutdown via the {@code shutDown()} method and {@code false}
   *          otherwise.
   */
  public boolean isShutDown()
  {
    return shutDown.get();
  }



  /**
   * Attempts to sleep for the specified length of time in milliseconds, subject
   * to the accuracy available within the JVM and underlying system.  It may
   * wake up prematurely if the wakeup method is called, or if the thread is
   * interrupted.  If {@code shutDown()} is called, then any active caller of
   * this method will return immediately, and subsequent calls will return
   * without sleeping.
   * <BR><BR>
   * This method must not be called on the same {@code WakeableSleeper} instance
   * by multiple threads at the same time.
   *
   * @param  time  The length of time in milliseconds to sleep.
   *
   * @return  {@code true} if the sleep completed, or {@code false} if it was
   *          woken or interrupted prematurely.
   */
  @ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
  public boolean sleep(final long time)
  {
    synchronized (wakeupCount)
    {
      if (isShutDown())
      {
        return false;
      }

      Validator.ensureTrue(sleeping.compareAndSet(false, true),
           "WakeableSleeper.sleep() must not be invoked concurrently by " +
                "multiple threads against the same instance.");

      try
      {
        final long beforeCount = wakeupCount.get();
        wakeupCount.wait(time);
        final long afterCount = wakeupCount.get();
        return (beforeCount == afterCount);
      }
      catch (final InterruptedException ie)
      {
        Debug.debugException(ie);
        return false;
      }
      finally
      {
        sleeping.set(false);
      }
    }
  }



  /**
   * Permanently shuts down this {@code WakeableSleeper} instance.  If a thread
   * is currently blocked in the {@code sleep} method, it will return
   * immediately, and all subsequent calls to that method will return without
   * sleeping.  It is safe to call this method multiple times.
   */
  @ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
  public void shutDown()
  {
    shutDown.set(true);
    wakeup();
  }



  /**
   * Indicates that the sleeper should wake up if it is currently sleeping.
   * This method will not make any attempt to ensure that the thread had woken
   * up before returning.  If multiple threads attempt to wake up the sleeper at
   * the same time, then it will have the same effect as a single wakeup
   * request.
   */
  @ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
  public void wakeup()
  {
    synchronized (wakeupCount)
    {
      wakeupCount.incrementAndGet();
      wakeupCount.notifyAll();
    }
  }
}
