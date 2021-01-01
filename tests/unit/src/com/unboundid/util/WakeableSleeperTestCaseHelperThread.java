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



import java.util.concurrent.atomic.AtomicBoolean;



/**
 * This class provides a helper thread that can be used by the wakeable sleeper
 * test case to wake up, interrupt, and/or test concurrent sleeping in the
 * {@code WakeableSleeper} class.
 */
public class WakeableSleeperTestCaseHelperThread
       extends Thread
{
  // The flag that will be used to indicate whether the
  private final AtomicBoolean successful;

  // Indicates whether to interrupt the sleeper.
  private final boolean interrupt;

  // Indicates whether to shutDown the sleeper.
  private final boolean shutDown;

  // Indicates whether to try a concurrent sleep.
  private final boolean trySleep;

  // Indicates whether to wake up the sleeper.
  private final boolean wakeUp;

  // The delay in milliseconds before taking the requested action.
  private final long delay;

  // A buffer holding the failure reason.
  private final StringBuilder failureReason;

  // The thread being used to sleep.
  private final Thread sleeperThread;

  // The wakeable sleeper.
  private final WakeableSleeper sleeper;



  /**
   * Creates a new wakeable sleeper test case helper thread that may be used to
   * prematurely wake up a sleeper.
   *
   * @param  sleeper   The wakeable sleeper to wake up.
   * @param  delay     The length of time in milliseconds to wait before calling
   *                   wakeup.
   * @param  trySleep  Indicates whether to try a concurrent sleep before waking
   *                   up the sleeper.
   */
  public WakeableSleeperTestCaseHelperThread(final WakeableSleeper sleeper,
                                             final long delay,
                                             final boolean trySleep)
  {
    this.sleeper  = sleeper;
    this.delay    = delay;
    this.trySleep = trySleep;

    interrupt     = false;
    shutDown      = false;
    wakeUp        = true;
    sleeperThread = null;
    successful    = new AtomicBoolean(false);
    failureReason = new StringBuilder();
  }



  /**
   * Creates a new wakeable sleeper test case helper thread that may be used to
   * prematurely interrupt a sleeper.
   *
   * @param  sleeper        The wakeable sleeper to interrupt.
   * @param  sleeperThread  The thread that is doing the sleeping.
   * @param  delay          The length of time in milliseconds to wait before
   *                        interrupting the sleeper thread thread.
   * @param  trySleep       Indicates whether to try a concurrent sleep before
   *                        interrupting the sleeper thread.
   */
  public WakeableSleeperTestCaseHelperThread(final WakeableSleeper sleeper,
                                             final Thread sleeperThread,
                                             final long delay,
                                             final boolean trySleep)
  {
    this.sleeper       = sleeper;
    this.sleeperThread = sleeperThread;
    this.delay         = delay;
    this.trySleep      = trySleep;

    interrupt     = true;
    shutDown      = false;
    wakeUp        = false;
    successful    = new AtomicBoolean(false);
    failureReason = new StringBuilder();
  }



  /**
   * Creates a new wakeable sleeper test case helper thread that may be used to
   * shutdown a sleeper.
   *
   * @param  sleeper        The wakeable sleeper to interrupt.
   * @param  delay          The length of time in milliseconds to wait before
   *                        interrupting the sleeper thread thread.
   */
  public WakeableSleeperTestCaseHelperThread(final WakeableSleeper sleeper,
                                             final long delay)
  {
    this.sleeper       = sleeper;
    this.delay         = delay;

    interrupt     = false;
    sleeperThread = null;
    shutDown      = true;
    trySleep      = false;
    wakeUp        = false;
    successful    = new AtomicBoolean(false);
    failureReason = new StringBuilder();
  }



  /**
   * Sleeps for the specified delay before optionally attempting a concurrent
   * sleep and then waking up, interrupting, or shutting down the sleeper.
   */
  @Override()
  public void run()
  {
    boolean success = true;

    try
    {
      if (delay > 0)
      {
        Thread.sleep(delay);
      }
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }

    if (trySleep)
    {
      try
      {
        sleeper.sleep(1L);
        success = false;
        failureReason.append("Concurrent sleep did not throw an exception.");
      }
      catch (LDAPSDKUsageException lsue)
      {
        // This was expected.
      }
      catch (Throwable t)
      {
        success = false;
        failureReason.append("Concurrent sleep threw " + String.valueOf(t) +
                             " rather than LDAPSDKUsageException");
      }
    }

    if (wakeUp)
    {
      sleeper.wakeup();
    }
    else if (interrupt)
    {
      sleeperThread.interrupt();
    }
    else if (shutDown)
    {
      sleeper.shutDown();
    }

    successful.set(success);
  }



  /**
   * Indicates whether the processing performed by this thread was successful.
   *
   * @return  {@code true} if the processing was successful, or {@code false} if
   *          not.
   */
  public boolean successful()
  {
    return successful.get();
  }



  /**
   * Retrieves the failure reason that can explain why the processing was not
   * successful.
   *
   * @return  The failure reason to explain why the processing was not
   *          successful, or an empty string if no failure reason is available
   *          or the processing was successful.
   */
  public String getFailureReason()
  {
    return failureReason.toString();
  }
}
