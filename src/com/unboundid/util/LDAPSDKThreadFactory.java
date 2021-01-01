/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;



/**
 * This class provides a thread factory implementation that may be used to
 * create threads with a number of basic settings.  The name of each thread will
 * be followed by a counter indicating the order in which the thread was
 * created.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPSDKThreadFactory
       implements ThreadFactory
{
  // The counter that will be used for the thread number.
  @NotNull private final AtomicLong threadCounter;

  // Indicates whether the threads should be created as daemon threads.
  private final boolean daemon;

  // The base name to use for newly-created threads.
  @NotNull private final String baseName;

  // The thread group that should be used for the threads.
  @Nullable private final ThreadGroup threadGroup;



  /**
   * Creates a new instance of this thread factory with the provided settings.
   * Threads created will have the default thread group.
   *
   * @param  baseName  The base name to use for threads created by this factory.
   * @param  daemon    Indicates whether the threads should be created as daemon
   *                   threads.
   */
  public LDAPSDKThreadFactory(@NotNull final String baseName,
                              final boolean daemon)
  {
    this(baseName, daemon, null);
  }



  /**
   * Creates a new instance of this thread factory with the provided settings.
   *
   * @param  baseName     The base name to use for threads created by this
   *                      factory.  It must not be {@code null}.
   * @param  daemon       Indicates whether the threads should be created as
   *                      daemon threads.
   * @param  threadGroup  The thread group to use for threads created by this
   *                      factory.  It may be {@code null} if the default thread
   *                      group should be used.
   */
  public LDAPSDKThreadFactory(@NotNull final String baseName,
                              final boolean daemon,
                              @Nullable final ThreadGroup threadGroup)
  {
    this.baseName     = baseName;
    this.daemon       = daemon;
    this.threadGroup  = threadGroup;

    threadCounter = new AtomicLong(1L);
  }



  /**
   * Creates a new thread using the settings for this thread factory.  The new
   * thread will not be started.
   *
   * @param  r  The {@code Runnable} target that will be used for the actual
   *            thread logic.  It must not be {@code null}.
   *
   * @return  The newly-created (but not yet started) thread.
   */
  @Override()
  @NotNull()
  public Thread newThread(@NotNull final Runnable r)
  {
    final String name = baseName + ' ' + threadCounter.getAndIncrement();
    final Thread t = new Thread(threadGroup, r, name);
    t.setDaemon(daemon);
    return t;
  }
}
