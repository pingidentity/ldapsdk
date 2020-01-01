/*
 * Copyright 2018-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2018-2020 Ping Identity Corporation
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
 * {@code CloseableLock} class.
 */
final class CloseableLockTestCaseThread
      extends Thread
{
  // Indicates whether the thread currently holds the lock.
  private final AtomicBoolean isLocked;

  // Indicates whether the other thread has failed an attempt to acquire the
  // lock.
  private final AtomicBoolean tryLockFailed;

  // The lock to use for testing.
  private final CloseableLock lock;



  /**
   * Creates a new instance of this thread with the provided information.
   *
   * @param  lock           The lock that will be used for testing.
   * @param  isLocked       An {@code AtomicBoolean} instance that this thread
   *                        will update once it has acquired the lock.
   * @param  tryLockFailed  An {@code AtomicBoolean} value that the
   *                        {@code CloseableLockTestCase} instance will update
   *                        once it has failed to acquire the lock.
   */
  CloseableLockTestCaseThread(final CloseableLock lock,
                              final AtomicBoolean isLocked,
                              final AtomicBoolean tryLockFailed)
  {
    Validator.ensureNotNull(lock);
    Validator.ensureFalse(isLocked.get());
    Validator.ensureFalse(tryLockFailed.get());

    setName("CloseableLockTestCase Thread");
    setDaemon(true);

    this.lock = lock;
    this.isLocked = isLocked;
    this.tryLockFailed = tryLockFailed;

  }



  /**
   * Acquires the lock and waits for the {@code CloseableLockTestCase} thread to
   * fail to acquire it.
   */
  @Override()
  public void run()
  {
    Validator.ensureFalse(isLocked.get());
    Validator.ensureFalse(tryLockFailed.get());

    try (CloseableLock.Lock l = lock.lock())
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
