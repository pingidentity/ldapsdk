/*
 * Copyright 2018-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2025 Ping Identity Corporation
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
 * Copyright (C) 2018-2025 Ping Identity Corporation
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
 * This class provides a background thread that can be used in testing the
 * {@code CloseableReadWriteLock} class.
 */
final class CloseableReadWriteLockTestCaseThread
      extends Thread
{
  // Indicates whether the thread currently holds the lock.
  private final AtomicBoolean isLocked;

  // Indicates whether the other thread has failed an attempt to acquire the
  // lock.
  private final AtomicBoolean tryLockFailed;

  // Indicates whether this thread should acquire the write lock or the read
  // lock.
  private final boolean acquireWriteLock;

  // The lock to use for testing.
  private final CloseableReadWriteLock lock;



  /**
   * Creates a new instance of this thread with the provided information.
   *
   * @param  lock              The lock that will be used for testing.
   * @param  acquireWriteLock  Indicates whether this thread should acquire the
   *                           write lock (if {@code true}) or the read lock (if
   *                           {@code false}).
   * @param  isLocked          An {@code AtomicBoolean} instance that this
   *                           thread will update once it has acquired the lock.
   * @param  tryLockFailed     An {@code AtomicBoolean} value that the
   *                           {@code CloseableReadWriteLockTestCase} instance
   *                           will update once it has failed to acquire the
   *                           lock.
   */
  CloseableReadWriteLockTestCaseThread(final CloseableReadWriteLock lock,
                                       final boolean acquireWriteLock,
                                       final AtomicBoolean isLocked,
                                       final AtomicBoolean tryLockFailed)
  {
    Validator.ensureNotNull(lock);
    Validator.ensureFalse(isLocked.get());
    Validator.ensureFalse(tryLockFailed.get());

    setName("CloseableReadWriteLockTestCase Thread (acquireWriteLock=" +
         acquireWriteLock + ')');
    setDaemon(true);

    this.lock = lock;
    this.acquireWriteLock = acquireWriteLock;
    this.isLocked = isLocked;
    this.tryLockFailed = tryLockFailed;

  }



  /**
   * Acquires the lock and waits for the {@code CloseableReadWriteLockTestCase}
   * thread to fail to acquire it.
   */
  @Override()
  public void run()
  {
    Validator.ensureFalse(isLocked.get());
    Validator.ensureFalse(tryLockFailed.get());

    if (acquireWriteLock)
    {
      try (CloseableReadWriteLock.WriteLock l = lock.lockWrite())
      {
        l.avoidCompilerWarning();
        isLocked.set(true);

        while (! tryLockFailed.get())
        {
          try
          {
            Thread.sleep(1L);
          }
          catch (final Exception e)
          {
            Thread.yield();
          }
        }
      }
    }
    else
    {
      try (CloseableReadWriteLock.ReadLock l = lock.lockRead())
      {
        l.avoidCompilerWarning();
        isLocked.set(true);

        while (! tryLockFailed.get())
        {
          try
          {
            Thread.sleep(1L);
          }
          catch (final Exception e)
          {
            Thread.yield();
          }
        }
      }
    }
  }
}
