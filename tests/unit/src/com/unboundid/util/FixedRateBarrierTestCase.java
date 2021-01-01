/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
import org.testng.annotations.DataProvider;

/**
 * This class provides a set of test cases for the FixedRateBarrier class.
 */
public class FixedRateBarrierTestCase
        extends UtilTestCase
{

  /**
   * Tests that {@code await} operates at the proper rate.
   *
   * @param  intervalDurationMS  The interval duration to use when constructing
   *                             the FixedRateBarrier.
   * @param  perInterval         The per interval value to use when constructing
   *                             the FixedRateBarrier.
   * @param  numAwaitCalls       The number of times to call await.
   * @param  countPerAwait       The count to pass into await.
   * @param  minTimeMS           The minimum number of milliseconds that calling
   *                             await for the specified amount of time should
   *                             take.
   * @param  maxTimeMS           The maximum number of milliseconds that calling
   *                             await for the specified amount of time should
   *                             take.
   */
  @Test(dataProvider = "getTestAwaitParams")
  public void testAwait(final long intervalDurationMS,
                        final int perInterval,
                        final int numAwaitCalls,
                        final int countPerAwait,
                        final long minTimeMS,
                        final long maxTimeMS)
  {
    FixedRateBarrier barrier = new FixedRateBarrier(intervalDurationMS,
                                                    perInterval);
    assertEquals(barrier.getTargetRate().getFirst().longValue(),
         intervalDurationMS);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), perInterval);
    long startMS = System.currentTimeMillis();

    for (int i = 0; i < numAwaitCalls; i++)
    {
      final boolean isShutdownRequested;
      if (countPerAwait == 1)
      {
        isShutdownRequested = barrier.await();
      }
      else
      {
        isShutdownRequested = barrier.await(countPerAwait);
      }
      assertTrue(!isShutdownRequested);
    }

    long durationMS = System.currentTimeMillis() - startMS;

    assertTrue(durationMS >= minTimeMS, "durationMS=" + durationMS);
    assertTrue(durationMS <= maxTimeMS, "durationMS=" + durationMS);

    assertFalse(barrier.isShutdownRequested());
    barrier.shutdownRequested();
    assertTrue(barrier.isShutdownRequested());

    boolean isShutdownRequested = barrier.await();
    assertTrue(isShutdownRequested);
  }



  /**
   * Constructs the parameters to use for the {@code testAwait} method.
   *
   * @return  A set of test cases that can be used to call {@code testAwait}.
   */
  @DataProvider
  public Object[][] getTestAwaitParams()
  {
    // We actually do a lot better than this in terms of accuracy,
    // but we have very conservative estimates to avoid false positives
    // with test failures.
    return new Object[][]{
         //           interval-ms  per-interval  #await  count  min-ms  max-ms
         new Object[]{        100,          100,    100,     1,     50,    150},
         new Object[]{        100,           10,     20,     1,    100,    400},
         new Object[]{       1000,         1000,     10,     1,      0,    100},

         new Object[]{        100,          100,     20,     5,     50,    150},
         new Object[]{        100,           10,      4,     5,    100,    400},
         new Object[]{       1000,         1000,      2,     5,      0,    100},

         new Object[]{        100,          100,      5,    20,     50,    150},
    };
  }



  /**
   * Tests the {@link FixedRateBarrier#await(int)} method with values that are
   * at, near, or in excess of the boundary conditions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAwaitWithBoundaryValues()
         throws Exception
  {
    final FixedRateBarrier barrier = new FixedRateBarrier(1000L, 100);
    assertFalse(barrier.await(0));
    assertFalse(barrier.await(-1));

    try
    {
      barrier.await(1001);
      fail("Expected an exception with an await argument that exceeds " +
           "perInterval");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests that {@code setRate} operates at the proper rate.
   *
   * This test is currently disabled because it fails occasionally in the
   * continuous build.  It could be rewritten to not use a thread in the
   * background.
   *
   * @param  initialIntervalDurationMS  The interval duration to use when
   *                                    constructing the FixedRateBarrier.
   * @param  initialPerInterval         The per interval value to use when
   *                                    constructing the FixedRateBarrier.
   * @param  millisBeforeSettingRate    The time to wait before calling setRate.
   * @param  updatedIntervalDurationMS  The interval duration to use when
   *                                    updating the FixedRateBarrier.
   * @param  updatedPerInterval         The per interval value to use when
   *                                    updating the FixedRateBarrier.
   * @param  totalAwaitCalls            The number of times to call await.
   * @param  minTimeMS                  The minimum number of milliseconds that
   *                                    calling await for the specified amount
   *                                    of time should take.
   * @param  maxTimeMS                  The maximum number of milliseconds that
   *                                    calling await for the specified amount
   *                                    of time should take.
   */
  @Test(dataProvider = "getTestSetRateParams", enabled = false)
  public void testSetRate(final long initialIntervalDurationMS,
                          final int initialPerInterval,
                          final long millisBeforeSettingRate,
                          final long updatedIntervalDurationMS,
                          final int updatedPerInterval,
                          final int totalAwaitCalls,
                          final long minTimeMS,
                          final long maxTimeMS)
  {
    final FixedRateBarrier barrier = new FixedRateBarrier(
         initialIntervalDurationMS, initialPerInterval);
    assertEquals(barrier.getTargetRate().getFirst().longValue(),
                 initialIntervalDurationMS);
    assertEquals(barrier.getTargetRate().getSecond().intValue(),
         initialPerInterval);

    final long startMS = System.currentTimeMillis();

    Thread t = new UpdateRateInFuture(barrier, millisBeforeSettingRate,
         updatedIntervalDurationMS, updatedPerInterval);
    t.start();

    for (int i = 0; i < totalAwaitCalls; i++)
    {
      boolean isShutdownRequested = barrier.await();
      assertTrue(!isShutdownRequested);
    }

    long durationMS = System.currentTimeMillis() - startMS;

    assertEquals(barrier.getTargetRate().getFirst().longValue(),
                 updatedIntervalDurationMS);
    assertEquals(barrier.getTargetRate().getSecond().intValue(),
                 updatedPerInterval);

    assertTrue(durationMS >= minTimeMS, "durationMS=" + durationMS);
    assertTrue(durationMS <= maxTimeMS, "durationMS=" + durationMS);

    assertFalse(barrier.isShutdownRequested());
    barrier.shutdownRequested();
    assertTrue(barrier.isShutdownRequested());

    boolean isShutdownRequested = barrier.await();
    assertTrue(isShutdownRequested);
  }



  /**
   * Constructs the parameters to use for the {@code testSetRate} method.
   *
   * @return  A set of test cases that can be used to call {@code testSetRate}.
   */
  @DataProvider
  public Object[][] getTestSetRateParams()
  {
    // We actually do a lot better than this in terms of accuracy,
    // but we have very conservative estimates to avoid false positives
    // with test failures.
    return new Object[][]{
           // Start off with a very slow rate, and then switch to a fast one.
           //           Init Rate   Wait   New Rate    Awaits   Await Time Range
           new Object[]{10000, 1,   100,   100, 100,   200,     150, 500},

           // Start off with a fast rate, and then switch to a slower one.
           //           Init Rate   Wait   New Rate    Awaits   Await Time Range
           new Object[]{500, 100,   500,   100, 10,    400,     550, 4000}
    };
  }



  /**
   * Sets the rate on a FixedRateBarrier in the background after a specified
   * delay.
   */
  private static class UpdateRateInFuture extends Thread
  {
    private final FixedRateBarrier barrier;
    private final long afterMillis;
    private final long intervalDurationMS;
    private final int perInterval;



    /**
     * Constructor.
     *
     * @param  barrier             The barrier to update.
     * @param  delayMillis         Time to wait before setting the rate.
     * @param  intervalDurationMS  The interval duration to use when updating
     *                             the FixedRateBarrier.
     * @param  perInterval         The per interval value to use when updating
     *                             the FixedRateBarrier.
     */
    UpdateRateInFuture(final FixedRateBarrier barrier, final long delayMillis,
                       final long intervalDurationMS, final int perInterval)
    {
      this.barrier = barrier;
      this.afterMillis = delayMillis;
      this.intervalDurationMS = intervalDurationMS;
      this.perInterval = perInterval;

      setDaemon(true);
    }



    /**
     * Sets the rate after the specified delay.
     */
    @Override
    public void run()
    {
      try
      {
        if (afterMillis > 0)
        {
          Thread.sleep(afterMillis);
        }
      }
      catch (InterruptedException e)
      {
        e.printStackTrace();
      }
      barrier.setRate(intervalDurationMS, perInterval);
    }
  }
}
