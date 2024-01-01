/*
 * Copyright 2023-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023-2024 Ping Identity Corporation
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
 * Copyright (C) 2023-2024 Ping Identity Corporation
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
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.util.NotNull;
import com.unboundid.util.WakeableSleeper;



/**
 * This class provides a thread that can be used to monitor the connection pools
 * associated with a {@link PooledReferralConnector} instance, destroying them
 * as needed based on the time they were created and/or last used.
 */
final class PooledReferralConnectorBackgroundThread
      extends Thread
{
  // A flag that indicates whether the thread should stop running.
  @NotNull private final AtomicBoolean shutDownRequested;

  // The interval in milliseconds to use when sleeping between checks.
  private final long checkIntervalMillis;

  // The map of connection pools that have been created for the associated
  // referral connector, indexed by the address and port of the target server.
  @NotNull private final Map<String,List<ReferralConnectionPool>>
       poolsByHostPort;

  // The maximum length of time in milliseconds that any connection pool should
  // be allowed to remain active.
  private final long maximumPoolAgeMillis;

  // The maximum length of time in milliseconds that should be allowed to pass
  // since a connection pool was last used to follow a referral before it is
  // discarded.
  private final long maximumPoolIdleDurationMillis;

  // A sleeper that will be used to pause between checks.
  @NotNull private final WakeableSleeper sleeper;



  /**
   * Creates a new instance of this thread with the provided information.
   *
   * @param  referralConnector  The referral connector instance with which this
   *                            thread is associated.  It must not be
   *                            {@code null}.
   */
  PooledReferralConnectorBackgroundThread(
       @NotNull final PooledReferralConnector referralConnector)
  {
    setName("Pooled Referral Connector Background Thread");
    setDaemon(true);

    poolsByHostPort = referralConnector.getPoolsByHostPort();
    checkIntervalMillis =
         referralConnector.getBackgroundThreadCheckIntervalMillis();
    maximumPoolAgeMillis = referralConnector.getMaximumPoolAgeMillis();
    maximumPoolIdleDurationMillis =
         referralConnector.getMaximumPoolIdleDurationMillis();

    shutDownRequested = new AtomicBoolean(false);
    sleeper = new WakeableSleeper();
  }



  /**
   * Operates in a loop, checking the set of connection pools to determine
   * whether any of them should be destroyed.
   */
  @Override()
  public void run()
  {
    while (! shutDownRequested.get())
    {
      synchronized (poolsByHostPort)
      {
        final long currentTime = System.currentTimeMillis();
        for (final List<ReferralConnectionPool> poolList :
             poolsByHostPort.values())
        {
          final Iterator<ReferralConnectionPool> iterator =
               poolList.iterator();
          while (iterator.hasNext())
          {
            final ReferralConnectionPool pool = iterator.next();
            if (maximumPoolAgeMillis > 0L)
            {
              final long poolAgeMillis = currentTime -
                   pool.getPoolCreateTimeMillis();
              if (poolAgeMillis > maximumPoolAgeMillis)
              {
                iterator.remove();
                pool.close();
              }
            }

            if (maximumPoolIdleDurationMillis > 0L)
            {
              final long poolIdleDurationMillis =
                   currentTime - pool.getLastUsedTimeMillis();
              if (poolIdleDurationMillis > maximumPoolIdleDurationMillis)
              {
                iterator.remove();
                pool.close();
              }
            }
          }
        }
      }

      sleeper.sleep(checkIntervalMillis);
    }
  }



  /**
   * Requests that this thread stop running.
   */
  void shutDown()
  {
    shutDownRequested.set(true);
    sleeper.wakeup();
  }
}
