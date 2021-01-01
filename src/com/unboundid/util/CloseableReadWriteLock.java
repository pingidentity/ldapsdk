/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import java.io.Closeable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides an implementation of a reentrant read-write lock that can
 * be used with the Java try-with-resources facility.  With a read-write lock,
 * either exactly one thread can hold the write lock while no other threads hold
 * read locks, or zero or more threads can hold read locks while no thread holds
 * the write lock.  The one exception to this policy is that the thread that
 * holds the write lock can downgrade will be permitted to acquire a read lock
 * before it releases the write lock to downgrade from a write lock to a read
 * lock while ensuring that no other thread is permitted to acquire the write
 * lock while it is in the process of downgrading.
 * <BR><BR>
 * This class does not implement the
 * {@code java.util.concurrent.locks.ReadWriteLock} interface in order to ensure
 * that it can only be used through the try-with-resources mechanism, but it
 * uses a {@code java.util.concurrent.locks.ReentrantReadWriteLock} behind the
 * scenes to provide its functionality.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates how to use this lock using the Java
 * try-with-resources facility:
 * <PRE>
 * // Wait for up to 5 seconds to acquire the lock.
 * try (CloseableReadWriteLock.WriteLock writeLock =
 *           closeableReadWriteLock.tryLock(5L, TimeUnit.SECONDS))
 * {
 *   // NOTE:  If you don't reference the lock object inside the try block, the
 *   // compiler will issue a warning.
 *   writeLock.avoidCompilerWarning();
 *
 *   // Do something while the lock is held.  The lock will automatically be
 *   // released once code execution leaves this block.
 * }
 * catch (final InterruptedException e)
 * {
 *   // The thread was interrupted before the lock could be acquired.
 * }
 * catch (final TimeoutException)
 * {
 *   // The lock could not be acquired within the specified 5-second timeout.
 * }
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CloseableReadWriteLock
{
  // The closeable read lock.
  @NotNull private final ReadLock readLock;

  // The Java lock that is used behind the scenes for all locking functionality.
  @NotNull private final ReentrantReadWriteLock readWriteLock;

  // The closeable write lock.
  @NotNull private final WriteLock writeLock;



  /**
   * Creates a new instance of this read-write lock with a non-fair ordering
   * policy.
   */
  public CloseableReadWriteLock()
  {
    this(false);
  }



  /**
   * Creates a new instance of this read-write lock with the specified ordering
   * policy.
   *
   * @param  fair  Indicates whether the lock should use fair ordering.  If
   *               {@code true}, then if multiple threads are waiting on the
   *               lock, then the one that has been waiting the longest is the
   *               one that will get it.  If {@code false}, then no guarantee
   *               will be made about the order.  Fair ordering can incur a
   *               performance penalty.
   */
  public CloseableReadWriteLock(final boolean fair)
  {
    readWriteLock = new ReentrantReadWriteLock(fair);
    readLock = new ReadLock(readWriteLock.readLock());
    writeLock = new WriteLock(readWriteLock.writeLock());
  }



  /**
   * Acquires the write lock, blocking until the lock is available.
   *
   * @return  The {@link WriteLock} instance that may be used to perform the
   *          unlock via the try-with-resources facility.
   */
  @NotNull()
  public WriteLock lockWrite()
  {
    readWriteLock.writeLock().lock();
    return writeLock;
  }



  /**
   * Acquires the write lock, blocking until the lock is available.
   *
   * @return  The {@link WriteLock} instance that may be used to perform the
   *          unlock via the try-with-resources facility.
   *
   * @throws  InterruptedException  If the thread is interrupted while waiting
   *                                to acquire the lock.
   */
  @NotNull()
  public WriteLock lockWriteInterruptibly()
         throws InterruptedException
  {
    readWriteLock.writeLock().lockInterruptibly();
    return writeLock;
  }



  /**
   * Tries to acquire the write lock, waiting up to the specified length of time
   * for it to become available.
   *
   * @param  waitTime  The maximum length of time to wait for the lock.  It must
   *                   be greater than zero.
   * @param  timeUnit  The time unit that should be used when evaluating the
   *                   {@code waitTime} value.
   *
   * @return  The {@link WriteLock} instance that may be used to perform the
   *          unlock via the try-with-resources facility.
   *
   * @throws  InterruptedException  If the thread is interrupted while waiting
   *                                to acquire the lock.
   *
   * @throws  TimeoutException  If the lock could not be acquired within the
   *                            specified length of time.
   */
  @NotNull()
  public WriteLock tryLockWrite(final long waitTime,
                                @NotNull final TimeUnit timeUnit)
         throws InterruptedException, TimeoutException
  {
    if (waitTime <= 0)
    {
      Validator.violation(
           "CloseableLock.tryLockWrite.waitTime must be greater than zero.  " +
                "The provided value was " + waitTime);
    }

    if (readWriteLock.writeLock().tryLock(waitTime, timeUnit))
    {
      return writeLock;
    }
    else
    {
      throw new TimeoutException(
           ERR_CLOSEABLE_RW_LOCK_TRY_LOCK_WRITE_TIMEOUT.get(
                StaticUtils.millisToHumanReadableDuration(
                     timeUnit.toMillis(waitTime))));
    }
  }



  /**
   * Acquires a read lock, blocking until the lock is available.
   *
   * @return  The {@link ReadLock} instance that may be used to perform the
   *          unlock via the try-with-resources facility.
   */
  @NotNull()
  public ReadLock lockRead()
  {
    readWriteLock.readLock().lock();
    return readLock;
  }



  /**
   * Acquires a read lock, blocking until the lock is available.
   *
   * @return  The {@link ReadLock} instance that may be used to perform the
   *          unlock via the try-with-resources facility.
   *
   * @throws  InterruptedException  If the thread is interrupted while waiting
   *                                to acquire the lock.
   */
  @NotNull()
  public ReadLock lockReadInterruptibly()
         throws InterruptedException
  {
    readWriteLock.readLock().lockInterruptibly();
    return readLock;
  }



  /**
   * Tries to acquire a read lock, waiting up to the specified length of time
   * for it to become available.
   *
   * @param  waitTime  The maximum length of time to wait for the lock.  It must
   *                   be greater than zero.
   * @param  timeUnit  The time unit that should be used when evaluating the
   *                   {@code waitTime} value.
   *
   * @return  The {@link ReadLock} instance that may be used to perform the
   *          unlock via the try-with-resources facility.
   *
   * @throws  InterruptedException  If the thread is interrupted while waiting
   *                                to acquire the lock.
   *
   * @throws  TimeoutException  If the lock could not be acquired within the
   *                            specified length of time.
   */
  @NotNull()
  public ReadLock tryLockRead(final long waitTime,
                              @NotNull final TimeUnit timeUnit)
         throws InterruptedException, TimeoutException
  {
    if (waitTime <= 0)
    {
      Validator.violation(
           "CloseableLock.tryLockRead.waitTime must be greater than zero.  " +
                "The provided value was " + waitTime);
    }

    if (readWriteLock.readLock().tryLock(waitTime, timeUnit))
    {
      return readLock;
    }
    else
    {
      throw new TimeoutException(
           ERR_CLOSEABLE_RW_LOCK_TRY_LOCK_READ_TIMEOUT.get(
                StaticUtils.millisToHumanReadableDuration(
                     timeUnit.toMillis(waitTime))));
    }
  }



  /**
   * Indicates whether this lock uses fair ordering.
   *
   * @return  {@code true} if this lock uses fair ordering, or {@code false} if
   *          not.
   */
  public boolean isFair()
  {
    return readWriteLock.isFair();
  }



  /**
   * Indicates whether the write lock is currently held by any thread.
   *
   * @return  {@code true} if the write lock is currently held by any thread, or
   *          {@code false} if not.
   */
  public boolean isWriteLocked()
  {
    return readWriteLock.isWriteLocked();
  }



  /**
   * Indicates whether the write lock is currently held by the current thread.
   *
   * @return  {@code true} if the write lock is currently held by the current
   *          thread, or {@code false} if not.
   */
  public boolean isWriteLockedByCurrentThread()
  {
    return readWriteLock.isWriteLockedByCurrentThread();
  }



  /**
   * Retrieves the number of holds that the current thread has on the write
   * lock.
   *
   * @return  The number of holds that the current thread has on the write lock.
   */
  public int getWriteHoldCount()
  {
    return readWriteLock.getWriteHoldCount();
  }



  /**
   * Retrieves the number of threads that currently hold the read lock.
   *
   * @return  The number of threads that currently hold the read lock.
   */
  public int getReadLockCount()
  {
    return readWriteLock.getReadLockCount();
  }



  /**
   * Retrieves the number of holds that the current thread has on the read lock.
   *
   * @return  The number of holds that the current thread has on the read lock.
   */
  public int getReadHoldCount()
  {
    return readWriteLock.getReadHoldCount();
  }



  /**
   * Indicates whether any threads are currently waiting to acquire either the
   * write or read lock.
   *
   * @return  {@code true} if any threads are currently waiting to acquire
   *          either the write or read lock, or {@code false} if not.
   */
  public boolean hasQueuedThreads()
  {
    return readWriteLock.hasQueuedThreads();
  }



  /**
   * Indicates whether the specified thread is currently waiting to acquire
   * either the write or read lock.
   *
   * @param  thread  The thread for which to make the determination.  It must
   *                 not be {@code null}.
   *
   * @return  {@code true} if the specified thread is currently waiting to
   *          acquire either the write or read lock, or {@code false} if not.
   */
  public boolean hasQueuedThread(@NotNull final Thread thread)
  {
    return readWriteLock.hasQueuedThread(thread);
  }



  /**
   * Retrieves an estimate of the number of threads currently waiting to acquire
   * either the write or read lock.
   *
   * @return  An estimate of the number of threads currently waiting to acquire
   *          either the write or read lock.
   */
  public int getQueueLength()
  {
    return readWriteLock.getQueueLength();
  }



  /**
   * Retrieves a string representation of this read-write lock.
   *
   * @return  A string representation of this read-write lock.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return "CloseableReadWriteLock(lock=" + readWriteLock.toString() + ')';
  }



  /**
   * This class provides a {@code Closeable} implementation that may be used to
   * unlock a {@link CloseableReadWriteLock}'s read lock via Java's
   * try-with-resources facility.
   */
  public final class ReadLock
         implements Closeable
  {
    // The associated read lock.
    @NotNull private final ReentrantReadWriteLock.ReadLock lock;



    /**
     * Creates a new instance with the provided lock.
     *
     * @param  lock  The lock that will be unlocked when the [@link #close()}
     *               method is called.  This must not be {@code null}.
     */
    private ReadLock(@NotNull final ReentrantReadWriteLock.ReadLock lock)
    {
      this.lock = lock;
    }



    /**
     * This method does nothing.  However, calling it inside a try block when
     * used in the try-with-resources framework can help avoid a compiler
     * warning that the JVM will give you if you don't reference the
     * {@code Closeable} object inside the try block.
     */
    public void avoidCompilerWarning()
    {
      // No implementation is required.
    }



    /**
     * Unlocks the associated lock.
     */
    @Override()
    public void close()
    {
      lock.unlock();
    }
  }



  /**
   * This class provides a {@code Closeable} implementation that may be used to
   * unlock a {@link CloseableReadWriteLock}'s write lock via Java's
   * try-with-resources facility.
   */
  public final class WriteLock
         implements Closeable
  {
    // The associated read lock.
    @NotNull private final ReentrantReadWriteLock.WriteLock lock;



    /**
     * Creates a new instance with the provided lock.
     *
     * @param  lock  The lock that will be unlocked when the [@link #close()}
     *               method is called.  This must not be {@code null}.
     */
    private WriteLock(@NotNull final ReentrantReadWriteLock.WriteLock lock)
    {
      this.lock = lock;
    }



    /**
     * This method does nothing.  However, calling it inside a try block when
     * used in the try-with-resources framework can help avoid a compiler
     * warning that the JVM will give you if you don't reference the
     * {@code Closeable} object inside the try block.
     */
    public void avoidCompilerWarning()
    {
      // No implementation is required.
    }



    /**
     * Unlocks the associated lock.
     */
    @Override()
    public void close()
    {
      lock.unlock();
    }
  }
}
