/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.WakeableSleeper;



/**
 * This class provides a thread that may be used to periodically display
 * progress information for the parallel update program.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class ParallelUpdateProgressMonitor
      extends Thread
{
  // Indicates whether a request has been made to stop running.
  private volatile boolean stopRequested;

  // The parallel update instance with which this thread is associated.
  @NotNull private final ParallelUpdate parallelUpdate;

  // The object that will be used for sleeping.
  @NotNull private final WakeableSleeper sleeper;



  /**
   * Creates a new instance of this progress monitor thread.
   *
   * @param  parallelUpdate  The parallel update instance with which this thread
   *                         is associated.
   */
  ParallelUpdateProgressMonitor(@NotNull final ParallelUpdate parallelUpdate)
  {
    super("Parallel Update Progress Monitor");

    this.parallelUpdate = parallelUpdate;
    stopRequested       = false;
    sleeper             = new WakeableSleeper();
  }



  /**
   * Operates in a loop, periodically causing the parallel update program to
   * print out progress information.
   */
  @Override()
  public void run()
  {
    while (! stopRequested)
    {
      sleeper.sleep(5000);
      parallelUpdate.printIntervalData();
    }
  }



  /**
   * Indicates that this thread should stop running.
   */
  void stopRunning()
  {
    stopRequested = true;
    sleeper.shutDown();
  }
}
