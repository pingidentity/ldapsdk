/*
 * Copyright 2021-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2024 Ping Identity Corporation
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
 * Copyright (C) 2021-2024 Ping Identity Corporation
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



import java.security.SecureRandom;



/**
 * This class provides a means of obtaining a thread-local {@code SecureRandom}
 * instance that can be used without synchronization or contention.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ThreadLocalSecureRandom
{
  /**
   * The thread-local instances that have been created.
   */
  @NotNull private static final ThreadLocal<SecureRandom> INSTANCES =
       new ThreadLocal<>();



  /**
   * Prevents this utility class from being instantiated.
   */
  private ThreadLocalSecureRandom()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a thread-local {@code SecureRandom} instance.
   *
   * @return  A thread-local {@code SecureRandom} instance.
   */
  @NotNull()
  public static SecureRandom get()
  {
    SecureRandom random = INSTANCES.get();
    if (random == null)
    {
      random = CryptoHelper.getSecureRandom();
      INSTANCES.set(random);
    }

    return random;
  }
}
