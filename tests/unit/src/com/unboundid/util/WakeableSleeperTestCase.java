/*
 * Copyright 2009-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2020 Ping Identity Corporation
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



import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the wakeable sleeper test case.
 */
public class WakeableSleeperTestCase
       extends UtilTestCase
{
  /**
   * Tests a case in which there is no wakeup or interruption.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoWakeupOrInterrupt()
         throws Exception
  {
    WakeableSleeper s = new WakeableSleeper();

    long startTime = System.currentTimeMillis();
    assertTrue(s.sleep(100L));
    long elapsedTime = System.currentTimeMillis() - startTime;
    assertTrue(elapsedTime >= 100L);
  }



  /**
   * Tests a case in which the sleeper is woken before the time expires.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWakeup()
         throws Exception
  {
    WakeableSleeper s = new WakeableSleeper();

    WakeableSleeperTestCaseHelperThread helper =
         new WakeableSleeperTestCaseHelperThread(s, 100L, false);
    helper.start();

    long startTime = System.currentTimeMillis();
    assertFalse(s.sleep(10000L));
    long elapsedTime = System.currentTimeMillis() - startTime;
    assertFalse(elapsedTime >= 10000L);

    helper.join();
    assertTrue(helper.successful(), helper.getFailureReason());
  }



  /**
   * Tests a case in which the sleeper is interrupted before the time expires.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInterrupt()
         throws Exception
  {
    WakeableSleeper s = new WakeableSleeper();

    WakeableSleeperTestCaseHelperThread helper =
         new WakeableSleeperTestCaseHelperThread(s, Thread.currentThread(),
                                                 100L, false);
    helper.start();

    long startTime = System.currentTimeMillis();
    assertFalse(s.sleep(10000L));
    long elapsedTime = System.currentTimeMillis() - startTime;
    assertFalse(elapsedTime >= 10000L);

    helper.join();
    assertTrue(helper.successful(), helper.getFailureReason());
  }



  /**
   * Tests a case in which the sleeper is woken before the time expires, and
   * include a concurrent sleep attempt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWakeupWithConcurrentSleep()
         throws Exception
  {
    WakeableSleeper s = new WakeableSleeper();

    WakeableSleeperTestCaseHelperThread helper =
         new WakeableSleeperTestCaseHelperThread(s, 100L, true);
    helper.start();

    long startTime = System.currentTimeMillis();
    assertFalse(s.sleep(10000L));
    long elapsedTime = System.currentTimeMillis() - startTime;
    assertFalse(elapsedTime >= 10000L);

    helper.join();
    assertTrue(helper.successful(), helper.getFailureReason());
  }



  /**
   * Tests a case in which the sleeper is interrupted before the time expires,
   * and include a concurrent sleep attempt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInterruptWithConcurrentSleep()
         throws Exception
  {
    WakeableSleeper s = new WakeableSleeper();

    WakeableSleeperTestCaseHelperThread helper =
         new WakeableSleeperTestCaseHelperThread(s, Thread.currentThread(),
                                                 100L, true);
    helper.start();

    long startTime = System.currentTimeMillis();
    assertFalse(s.sleep(10000L));
    long elapsedTime = System.currentTimeMillis() - startTime;
    assertFalse(elapsedTime >= 10000L);

    helper.join();
    assertTrue(helper.successful(), helper.getFailureReason());
  }



  /**
   * Tests the {@code shutDown()} and {@ isShutDown()} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShutDown()
         throws Exception
  {
    WakeableSleeper s = new WakeableSleeper();

    assertFalse(s.isShutDown());

    // This will shut the sleeper down after 100ms.
    WakeableSleeperTestCaseHelperThread helper =
         new WakeableSleeperTestCaseHelperThread(s, 100L);
    helper.start();

    // This sleeper should be woken up once the helper runs.
    long startTime = System.currentTimeMillis();
    assertFalse(s.sleep(10000L));
    long elapsedTime = System.currentTimeMillis() - startTime;
    assertFalse(elapsedTime >= 10000L);

    assertTrue(s.isShutDown());
    helper.join();

    // Subsequent sleeps should return immediately.
    startTime = System.currentTimeMillis();
    assertFalse(s.sleep(10000L));
    elapsedTime = System.currentTimeMillis() - startTime;
    assertFalse(elapsedTime >= 10000L);
  }
}
