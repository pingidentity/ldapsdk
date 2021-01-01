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



import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code CloseableReadWriteLock} class.
 */
public final class CloseableReadWriteLockTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests basic write lock functionality.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteLock()
         throws Exception
  {
    final CloseableReadWriteLock rwLock = new CloseableReadWriteLock();

    assertFalse(rwLock.isFair());
    assertFalse(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0);
    assertEquals(rwLock.getReadLockCount(), 0);
    assertEquals(rwLock.getReadHoldCount(), 0);
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());

    try (CloseableReadWriteLock.WriteLock l1 = rwLock.lockWrite())
    {
      l1.avoidCompilerWarning();

      assertFalse(rwLock.isFair());
      assertTrue(rwLock.isWriteLocked());
      assertTrue(rwLock.isWriteLockedByCurrentThread());
      assertEquals(rwLock.getWriteHoldCount(), 1);
      assertEquals(rwLock.getReadLockCount(), 0);
      assertEquals(rwLock.getReadHoldCount(), 0);
      assertFalse(rwLock.hasQueuedThreads());
      assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
      assertEquals(rwLock.getQueueLength(), 0);
      assertNotNull(rwLock.toString());

      try (CloseableReadWriteLock.WriteLock l2 =
                rwLock.lockWriteInterruptibly())
      {
        l2.avoidCompilerWarning();

        assertFalse(rwLock.isFair());
        assertTrue(rwLock.isWriteLocked());
        assertTrue(rwLock.isWriteLockedByCurrentThread());
        assertEquals(rwLock.getWriteHoldCount(), 2);
        assertEquals(rwLock.getReadLockCount(), 0);
        assertEquals(rwLock.getReadHoldCount(), 0);
        assertFalse(rwLock.hasQueuedThreads());
        assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
        assertEquals(rwLock.getQueueLength(), 0);
        assertNotNull(rwLock.toString());

        try (CloseableReadWriteLock.WriteLock l3 =
                  rwLock.tryLockWrite(1L, TimeUnit.SECONDS))
        {
          l3.avoidCompilerWarning();

          assertFalse(rwLock.isFair());
          assertTrue(rwLock.isWriteLocked());
          assertTrue(rwLock.isWriteLockedByCurrentThread());
          assertEquals(rwLock.getWriteHoldCount(), 3);
          assertEquals(rwLock.getReadLockCount(), 0);
          assertEquals(rwLock.getReadHoldCount(), 0);
          assertFalse(rwLock.hasQueuedThreads());
          assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
          assertEquals(rwLock.getQueueLength(), 0);
          assertNotNull(rwLock.toString());

          try (CloseableReadWriteLock.WriteLock l4 =
                    rwLock.tryLockWrite(0L, TimeUnit.SECONDS))
          {
            fail("Expected an exception when trying to acquire the write " +
                 "lock with a timeout of zero seconds.  Instead, got lock " +
                 l4);
          }
          catch (final LDAPSDKUsageException e)
          {
            // This was expected.
          }

          assertFalse(rwLock.isFair());
          assertTrue(rwLock.isWriteLocked());
          assertTrue(rwLock.isWriteLockedByCurrentThread());
          assertEquals(rwLock.getWriteHoldCount(), 3);
          assertEquals(rwLock.getReadLockCount(), 0);
          assertEquals(rwLock.getReadHoldCount(), 0);
          assertFalse(rwLock.hasQueuedThreads());
          assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
          assertEquals(rwLock.getQueueLength(), 0);
          assertNotNull(rwLock.toString());
        }

        assertFalse(rwLock.isFair());
        assertTrue(rwLock.isWriteLocked());
        assertTrue(rwLock.isWriteLockedByCurrentThread());
        assertEquals(rwLock.getWriteHoldCount(), 2);
        assertEquals(rwLock.getReadLockCount(), 0);
        assertEquals(rwLock.getReadHoldCount(), 0);
        assertFalse(rwLock.hasQueuedThreads());
        assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
        assertEquals(rwLock.getQueueLength(), 0);
        assertNotNull(rwLock.toString());
      }

      assertFalse(rwLock.isFair());
      assertTrue(rwLock.isWriteLocked());
      assertTrue(rwLock.isWriteLockedByCurrentThread());
      assertEquals(rwLock.getWriteHoldCount(), 1);
      assertEquals(rwLock.getReadLockCount(), 0);
      assertEquals(rwLock.getReadHoldCount(), 0);
      assertFalse(rwLock.hasQueuedThreads());
      assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
      assertEquals(rwLock.getQueueLength(), 0);
      assertNotNull(rwLock.toString());
    }

    assertFalse(rwLock.isFair());
    assertFalse(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0);
    assertEquals(rwLock.getReadLockCount(), 0);
    assertEquals(rwLock.getReadHoldCount(), 0);
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());
  }



  /**
   * Tests basic read lock functionality.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadLock()
         throws Exception
  {
    final CloseableReadWriteLock rwLock = new CloseableReadWriteLock(true);

    assertTrue(rwLock.isFair());
    assertFalse(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0);
    assertEquals(rwLock.getReadLockCount(), 0);
    assertEquals(rwLock.getReadHoldCount(), 0);
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());

    try (CloseableReadWriteLock.ReadLock l1 = rwLock.lockRead())
    {
      l1.avoidCompilerWarning();

      assertTrue(rwLock.isFair());
      assertFalse(rwLock.isWriteLocked());
      assertFalse(rwLock.isWriteLockedByCurrentThread());
      assertEquals(rwLock.getWriteHoldCount(), 0);
      assertEquals(rwLock.getReadLockCount(), 1);
      assertEquals(rwLock.getReadHoldCount(), 1);
      assertFalse(rwLock.hasQueuedThreads());
      assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
      assertEquals(rwLock.getQueueLength(), 0);
      assertNotNull(rwLock.toString());

      try (CloseableReadWriteLock.ReadLock l2 =
                rwLock.lockReadInterruptibly())
      {
        l2.avoidCompilerWarning();

        assertTrue(rwLock.isFair());
        assertFalse(rwLock.isWriteLocked());
        assertFalse(rwLock.isWriteLockedByCurrentThread());
        assertEquals(rwLock.getWriteHoldCount(), 0);
        assertEquals(rwLock.getReadLockCount(), 2);
        assertEquals(rwLock.getReadHoldCount(), 2);
        assertFalse(rwLock.hasQueuedThreads());
        assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
        assertEquals(rwLock.getQueueLength(), 0);
        assertNotNull(rwLock.toString());

        try (CloseableReadWriteLock.ReadLock l3 =
                  rwLock.tryLockRead(1L, TimeUnit.SECONDS))
        {
          l3.avoidCompilerWarning();

          assertTrue(rwLock.isFair());
          assertFalse(rwLock.isWriteLocked());
          assertFalse(rwLock.isWriteLockedByCurrentThread());
          assertEquals(rwLock.getWriteHoldCount(), 0);
          assertEquals(rwLock.getReadLockCount(), 3);
          assertEquals(rwLock.getReadHoldCount(), 3);
          assertFalse(rwLock.hasQueuedThreads());
          assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
          assertEquals(rwLock.getQueueLength(), 0);
          assertNotNull(rwLock.toString());

          try (CloseableReadWriteLock.ReadLock l4 =
                    rwLock.tryLockRead(0L, TimeUnit.SECONDS))
          {
            fail("Expected an exception when trying to acquire the read lock " +
                 "with a timeout of zero seconds.  Instead, got lock " + l4);
          }
          catch (final LDAPSDKUsageException e)
          {
            // This was expected.
          }

          assertTrue(rwLock.isFair());
          assertFalse(rwLock.isWriteLocked());
          assertFalse(rwLock.isWriteLockedByCurrentThread());
          assertEquals(rwLock.getWriteHoldCount(), 0);
          assertEquals(rwLock.getReadLockCount(), 3);
          assertEquals(rwLock.getReadHoldCount(), 3);
          assertFalse(rwLock.hasQueuedThreads());
          assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
          assertEquals(rwLock.getQueueLength(), 0);
          assertNotNull(rwLock.toString());
        }

        assertTrue(rwLock.isFair());
        assertFalse(rwLock.isWriteLocked());
        assertFalse(rwLock.isWriteLockedByCurrentThread());
        assertEquals(rwLock.getWriteHoldCount(), 0);
        assertEquals(rwLock.getReadLockCount(), 2);
        assertEquals(rwLock.getReadHoldCount(), 2);
        assertFalse(rwLock.hasQueuedThreads());
        assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
        assertEquals(rwLock.getQueueLength(), 0);
        assertNotNull(rwLock.toString());
      }

      assertTrue(rwLock.isFair());
      assertFalse(rwLock.isWriteLocked());
      assertFalse(rwLock.isWriteLockedByCurrentThread());
      assertEquals(rwLock.getWriteHoldCount(), 0);
      assertEquals(rwLock.getReadLockCount(), 1);
      assertEquals(rwLock.getReadHoldCount(), 1);
      assertFalse(rwLock.hasQueuedThreads());
      assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
      assertEquals(rwLock.getQueueLength(), 0);
      assertNotNull(rwLock.toString());
    }

    assertTrue(rwLock.isFair());
    assertFalse(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0);
    assertEquals(rwLock.getReadLockCount(), 0);
    assertEquals(rwLock.getReadHoldCount(), 0);
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());
  }



  /**
   * Tests to ensure that a write lock can be downgraded to a read lock.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteLockDowngrade()
         throws Exception
  {
    final CloseableReadWriteLock rwLock = new CloseableReadWriteLock(false);

    try (CloseableReadWriteLock.WriteLock writeLock = rwLock.lockWrite())
    {
      writeLock.avoidCompilerWarning();

      try (CloseableReadWriteLock.ReadLock readLock =
                rwLock.tryLockRead(1L, TimeUnit.SECONDS))
      {
        readLock.avoidCompilerWarning();
      }
    }
  }



  /**
   * Tests to ensure that a read lock can be upgraded to a write lock.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadLockUpgrade()
         throws Exception
  {
    final CloseableReadWriteLock rwLock = new CloseableReadWriteLock(true);

    try (CloseableReadWriteLock.ReadLock readLock = rwLock.lockRead())
    {
      readLock.avoidCompilerWarning();

      try (CloseableReadWriteLock.WriteLock writeLock =
                rwLock.tryLockWrite(10L, TimeUnit.MILLISECONDS))
      {
        fail("Expected an exception when trying to upgrade a read lock to " +
             "a write lock, but instead got " + writeLock);
      }
      catch (final TimeoutException e)
      {
        // This was expected.
        assertNotNull(e.getMessage());
      }
    }
  }



  /**
   * Tests the behavior when trying to acquire the write lock while another
   * thread already holds the write lock.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLockWriteWhileAnotherThreadAlreadyHoldsWriteLock()
         throws Exception
  {
    final CloseableReadWriteLock rwLock = new CloseableReadWriteLock();
    final AtomicBoolean isLocked = new AtomicBoolean(false);
    final AtomicBoolean tryLockFailed = new AtomicBoolean(false);

    assertFalse(rwLock.isFair());
    assertFalse(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0);
    assertEquals(rwLock.getReadLockCount(), 0);
    assertEquals(rwLock.getReadHoldCount(), 0);
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());

    final CloseableReadWriteLockTestCaseThread thread =
         new CloseableReadWriteLockTestCaseThread(rwLock, true, isLocked,
              tryLockFailed);
    thread.start();

    while (! isLocked.get())
    {
      Thread.sleep(1L);
    }

    assertFalse(rwLock.isFair());
    assertTrue(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0); // Not held by current thread
    assertEquals(rwLock.getReadLockCount(), 0);
    assertEquals(rwLock.getReadHoldCount(), 0);
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());

    try (CloseableReadWriteLock.WriteLock l =
              rwLock.tryLockWrite(1L, TimeUnit.MILLISECONDS))
    {
      fail("Expected to fail to acquire the write lock held by another " +
           "thread, but instead got " + l);
    }
    catch (final TimeoutException e)
    {
      // This was expected.
      assertNotNull(e.getMessage());
    }

    tryLockFailed.set(true);
    thread.join();
  }



  /**
   * Tests the behavior when trying to acquire the write lock while another
   * thread already holds the read lock.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLockWriteWhileAnotherThreadAlreadyHoldsReadLock()
         throws Exception
  {
    final CloseableReadWriteLock rwLock = new CloseableReadWriteLock();
    final AtomicBoolean isLocked = new AtomicBoolean(false);
    final AtomicBoolean tryLockFailed = new AtomicBoolean(false);

    assertFalse(rwLock.isFair());
    assertFalse(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0);
    assertEquals(rwLock.getReadLockCount(), 0);
    assertEquals(rwLock.getReadHoldCount(), 0);
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());

    final CloseableReadWriteLockTestCaseThread thread =
         new CloseableReadWriteLockTestCaseThread(rwLock, false, isLocked,
              tryLockFailed);
    thread.start();

    while (! isLocked.get())
    {
      Thread.sleep(1L);
    }

    assertFalse(rwLock.isFair());
    assertFalse(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0);
    assertEquals(rwLock.getReadLockCount(), 1);
    assertEquals(rwLock.getReadHoldCount(), 0); // Not held by current thread
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());

    // Verify that we can successfully acquire the read lock.
    try (CloseableReadWriteLock.ReadLock l =
              rwLock.tryLockRead(1L, TimeUnit.SECONDS))
    {
      l.avoidCompilerWarning();

      assertFalse(rwLock.isFair());
      assertFalse(rwLock.isWriteLocked());
      assertFalse(rwLock.isWriteLockedByCurrentThread());
      assertEquals(rwLock.getWriteHoldCount(), 0);
      assertEquals(rwLock.getReadLockCount(), 2);
      assertEquals(rwLock.getReadHoldCount(), 1);
      assertFalse(rwLock.hasQueuedThreads());
      assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
      assertEquals(rwLock.getQueueLength(), 0);
      assertNotNull(rwLock.toString());
    }

    assertFalse(rwLock.isFair());
    assertFalse(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0);
    assertEquals(rwLock.getReadLockCount(), 1);
    assertEquals(rwLock.getReadHoldCount(), 0); // Not held by current thread
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());


    // Verify that we cannot acquire the write lock.
    try (CloseableReadWriteLock.WriteLock l =
              rwLock.tryLockWrite(1L, TimeUnit.MILLISECONDS))
    {
      fail("Expected to fail to acquire the write lock while another thread " +
           "holds the read lock, but instead got " + l);
    }
    catch (final TimeoutException e)
    {
      // This was expected.
      assertNotNull(e.getMessage());
    }

    tryLockFailed.set(true);
    thread.join();
  }



  /**
   * Tests the behavior when trying to acquire the read lock while another
   * thread already holds the write lock.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLockReadWhileAnotherThreadAlreadyHoldsWriteLock()
         throws Exception
  {
    final CloseableReadWriteLock rwLock = new CloseableReadWriteLock();
    final AtomicBoolean isLocked = new AtomicBoolean(false);
    final AtomicBoolean tryLockFailed = new AtomicBoolean(false);

    assertFalse(rwLock.isFair());
    assertFalse(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0);
    assertEquals(rwLock.getReadLockCount(), 0);
    assertEquals(rwLock.getReadHoldCount(), 0);
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());

    final CloseableReadWriteLockTestCaseThread thread =
         new CloseableReadWriteLockTestCaseThread(rwLock, true, isLocked,
              tryLockFailed);
    thread.start();

    while (! isLocked.get())
    {
      Thread.sleep(1L);
    }

    assertFalse(rwLock.isFair());
    assertTrue(rwLock.isWriteLocked());
    assertFalse(rwLock.isWriteLockedByCurrentThread());
    assertEquals(rwLock.getWriteHoldCount(), 0); // Not held by current thread
    assertEquals(rwLock.getReadLockCount(), 0);
    assertEquals(rwLock.getReadHoldCount(), 0);
    assertFalse(rwLock.hasQueuedThreads());
    assertFalse(rwLock.hasQueuedThread(Thread.currentThread()));
    assertEquals(rwLock.getQueueLength(), 0);
    assertNotNull(rwLock.toString());

    try (CloseableReadWriteLock.ReadLock l =
              rwLock.tryLockRead(1L, TimeUnit.MILLISECONDS))
    {
      fail("Expected to fail to acquire the read lock while another thread " +
           "holds the write lock, but instead got " + l);
    }
    catch (final TimeoutException e)
    {
      // This was expected.
      assertNotNull(e.getMessage());
    }

    tryLockFailed.set(true);
    thread.join();
  }
}
