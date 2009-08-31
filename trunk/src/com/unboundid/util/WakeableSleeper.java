/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;



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
   * The object that we will place in the queue to trigger a wakeup.
   */
  private static final Object WAKEUP_OBJECT = new Object();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4758449685424440579L;



  // The queue that we will use to trigger a wakeup.
  private final ArrayBlockingQueue<Object> queue;

  // A flag used to prevent multiple concurrent attempts to sleep.
  private final AtomicBoolean sleeping;



  /**
   * Creates a new instance of this wakeable sleeper.
   */
  public WakeableSleeper()
  {
    queue    = new ArrayBlockingQueue<Object>(1);
    sleeping = new AtomicBoolean(false);
  }



  /**
   * Attempts to sleep for the specified length of time in milliseconds, subject
   * to the accuracy available within the JVM and underlying system.  It may
   * wake up prematurely if the wakeup method is called, or if the thread is
   * interrupted.
   * <BR><BR>
   * This method must not be called on the same instance by multiple threads at
   * the same time.
   *
   * @param  time  The length of time in milliseconds to sleep.
   *
   * @return  {@code true} if the sleep completed, or {@code false} if it was
   *          woken or interrupted prematurely.
   */
  @ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
  public boolean sleep(final long time)
  {
    Validator.ensureTrue(sleeping.compareAndSet(false, true),
         "WakeableSleeper.sleep() must not be invoked concurrently by " +
              "multiple threads against the same instance.");

    boolean completed = false;

    try
    {
      // First, poll with no timeout in order to remove any pending wakeup
      // object.  Then poll with the specified timeout.
      queue.poll();
      completed = (queue.poll(time, TimeUnit.MILLISECONDS) == null);
    }
    catch (InterruptedException ie)
    {
      Debug.debugException(ie);
    }

    sleeping.set(false);
    return completed;
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
    queue.offer(WAKEUP_OBJECT);
  }
}
