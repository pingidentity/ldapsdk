/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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



import java.util.Random;



/**
 * This class provides a means of obtaining a thread-local random number
 * generator that can be used by the current thread without the need for
 * synchronization.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ThreadLocalRandom
{
  /**
   * The random number generator that will be used to seed per-thread instances.
   */
  @NotNull private static final Random SEED_RANDOM = new Random();



  /**
   * The thread-local instances that have been created.
   */
  @NotNull private static final ThreadLocal<Random> INSTANCES =
       new ThreadLocal<>();



  /**
   * Prevents this class from being instantiated.
   */
  private ThreadLocalRandom()
  {
    // No implementation required.
  }



  /**
   * Gets a thread-local random number generator instance.
   *
   * @return  A thread-local random number generator instance.
   */
  @NotNull()
  public static Random get()
  {
    Random r = INSTANCES.get();
    if (r == null)
    {
      final long seed;
      synchronized (SEED_RANDOM)
      {
        seed = SEED_RANDOM.nextLong();
      }

      r = new Random(seed);
      INSTANCES.set(r);
    }

    return r;
  }
}
