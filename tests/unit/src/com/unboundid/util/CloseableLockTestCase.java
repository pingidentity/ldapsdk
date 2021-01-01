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
 * This class provides a set of test cases for the {@code CloseableLock} class.
 */
public final class CloseableLockTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests basic lock functionality.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLock()
         throws Exception
  {
    final CloseableLock lock = new CloseableLock();

    assertFalse(lock.isFair());
    assertFalse(lock.isLocked());
    assertFalse(lock.isHeldByCurrentThread());
    assertEquals(lock.getHoldCount(), 0);
    assertFalse(lock.hasQueuedThreads());
    assertFalse(lock.hasQueuedThread(Thread.currentThread()));
    assertEquals(lock.getQueueLength(), 0);
    assertNotNull(lock.toString());

    try (CloseableLock.Lock l1 = lock.lock())
    {
      l1.avoidCompilerWarning();

      assertFalse(lock.isFair());
      assertTrue(lock.isLocked());
      assertTrue(lock.isHeldByCurrentThread());
      assertEquals(lock.getHoldCount(), 1);
      assertFalse(lock.hasQueuedThreads());
      assertFalse(lock.hasQueuedThread(Thread.currentThread()));
      assertEquals(lock.getQueueLength(), 0);
      assertNotNull(lock.toString());

      try (CloseableLock.Lock l2 = lock.lockInterruptibly())
      {
        l2.avoidCompilerWarning();

        assertFalse(lock.isFair());
        assertTrue(lock.isLocked());
        assertTrue(lock.isHeldByCurrentThread());
        assertEquals(lock.getHoldCount(), 2);
        assertFalse(lock.hasQueuedThreads());
        assertFalse(lock.hasQueuedThread(Thread.currentThread()));
        assertEquals(lock.getQueueLength(), 0);
        assertNotNull(lock.toString());

        try (CloseableLock.Lock l3 = lock.tryLock(1L, TimeUnit.SECONDS))
        {
          l3.avoidCompilerWarning();

          assertFalse(lock.isFair());
          assertTrue(lock.isLocked());
          assertTrue(lock.isHeldByCurrentThread());
          assertEquals(lock.getHoldCount(), 3);
          assertFalse(lock.hasQueuedThreads());
          assertFalse(lock.hasQueuedThread(Thread.currentThread()));
          assertEquals(lock.getQueueLength(), 0);
          assertNotNull(lock.toString());

          try (CloseableLock.Lock l4 = lock.tryLock(0L, TimeUnit.SECONDS))
          {
            fail("Expected an exception when trying to acquire the lock with " +
                 "a timeout of zero seconds.  Instead, got lock " + l4);
          }
          catch (final LDAPSDKUsageException e)
          {
            // This was expected.
          }

          assertFalse(lock.isFair());
          assertTrue(lock.isLocked());
          assertTrue(lock.isHeldByCurrentThread());
          assertEquals(lock.getHoldCount(), 3);
          assertFalse(lock.hasQueuedThreads());
          assertFalse(lock.hasQueuedThread(Thread.currentThread()));
          assertEquals(lock.getQueueLength(), 0);
          assertNotNull(lock.toString());

          l3.avoidCompilerWarning();
        }

        assertFalse(lock.isFair());
        assertTrue(lock.isLocked());
        assertTrue(lock.isHeldByCurrentThread());
        assertEquals(lock.getHoldCount(), 2);
        assertFalse(lock.hasQueuedThreads());
        assertFalse(lock.hasQueuedThread(Thread.currentThread()));
        assertEquals(lock.getQueueLength(), 0);
        assertNotNull(lock.toString());

        l2.avoidCompilerWarning();
      }

      assertFalse(lock.isFair());
      assertTrue(lock.isLocked());
      assertTrue(lock.isHeldByCurrentThread());
      assertEquals(lock.getHoldCount(), 1);
      assertFalse(lock.hasQueuedThreads());
      assertFalse(lock.hasQueuedThread(Thread.currentThread()));
      assertEquals(lock.getQueueLength(), 0);
      assertNotNull(lock.toString());

      l1.avoidCompilerWarning();
    }

    assertFalse(lock.isFair());
    assertFalse(lock.isLocked());
    assertFalse(lock.isHeldByCurrentThread());
    assertEquals(lock.getHoldCount(), 0);
    assertFalse(lock.hasQueuedThreads());
    assertFalse(lock.hasQueuedThread(Thread.currentThread()));
    assertEquals(lock.getQueueLength(), 0);
    assertNotNull(lock.toString());
  }



  /**
   * Tests the behavior when trying to acquire the lock while it is held by
   * another thread.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLockThatIsAlreadyHeld()
         throws Exception
  {
    final CloseableLock lock = new CloseableLock(true);
    final AtomicBoolean isLocked = new AtomicBoolean(false);
    final AtomicBoolean tryLockFailed = new AtomicBoolean(false);

    assertTrue(lock.isFair());
    assertFalse(lock.isLocked());
    assertFalse(lock.isHeldByCurrentThread());
    assertEquals(lock.getHoldCount(), 0);
    assertFalse(lock.hasQueuedThreads());
    assertFalse(lock.hasQueuedThread(Thread.currentThread()));
    assertEquals(lock.getQueueLength(), 0);
    assertNotNull(lock.toString());

    final CloseableLockTestCaseThread thread =
         new CloseableLockTestCaseThread(lock, isLocked, tryLockFailed);
    thread.start();

    while (! isLocked.get())
    {
      Thread.sleep(1L);
    }

    assertTrue(lock.isFair());
    assertTrue(lock.isLocked());
    assertFalse(lock.isHeldByCurrentThread());
    assertEquals(lock.getHoldCount(), 0); // Not held by current thread.
    assertFalse(lock.hasQueuedThreads());
    assertFalse(lock.hasQueuedThread(Thread.currentThread()));
    assertEquals(lock.getQueueLength(), 0);
    assertNotNull(lock.toString());

    try (CloseableLock.Lock l = lock.tryLock(1L, TimeUnit.MILLISECONDS))
    {
      fail("Expected to fail to acquire the lock held by another thread, but " +
           "instead got " + l);
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
