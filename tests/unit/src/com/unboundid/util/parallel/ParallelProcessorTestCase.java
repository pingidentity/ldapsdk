/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.util.parallel;



import java.util.List;
import java.util.ArrayList;
import java.util.RandomAccess;
import java.util.concurrent.atomic.AtomicInteger;

import org.testng.annotations.Test;
import org.testng.annotations.DataProvider;

import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.UtilTestCase;



/**
 * Test class for ParallelProcessor.
 */
public class ParallelProcessorTestCase
     extends UtilTestCase
{

  /**
   * Constructs parameters for testBasics.
   *
   * @return Parameters for testBasics.
   */
  @DataProvider
  public Object[][] basicsParams()
  {
    return new Object[][]{
         new Object[]{ 1, 1, 10, null },
         new Object[]{ 2, 4, 100, null },
         new Object[]{ 8, 1, 1000, null },

         new Object[]{ 1, 1, 10, new AssertionError() },
         new Object[]{ 1, 1, 10, new RuntimeException() },
         new Object[]{ 2, 4, 100, new InterruptedException() },
         new Object[]{ 8, 1, 1000, new Throwable() },
    };
  }



  /**
   * Tests the basics of ParallelProcessor.
   *
   * @param numThreads   The number threads to use when constructing the
   *                     ParallelProcessor.
   * @param minPerThread The minimum items per thread to use when constructing
   *                     the ParallelProcessor.
   * @param maxItems     The maximum number of items to process.
   * @param failureCause The failure cause to throw when processing.
   *
   * @throws Exception If this test fails.
   */
  @Test(dataProvider = "basicsParams")
  public void testBasics(int numThreads, int minPerThread, int maxItems,
                         final Throwable failureCause)
       throws Exception
  {
    Processor<Integer, Integer> processor = new Processor<Integer, Integer>()
    {
      @Override()
      public Integer process(Integer input)
           throws Throwable
      {
        if (failureCause != null)
        {
          throw failureCause;
        }
        return input;
      }
    };

    ParallelProcessor<Integer, Integer> invoker =
         new ParallelProcessor<Integer, Integer>(
              processor, numThreads, minPerThread);

    try
    {
      // Process batches of different sizes starting with a batch size of 1.
      for (int numItems = 1; numItems <= maxItems; numItems *= 2)
      {
        List<Integer> inputItems = rangeList(0, numItems);

        List<Result<Integer, Integer>> results = invoker.processAll(inputItems);
        assertEquals(results.size(), numItems);

        // If invokeAll returns a list that isn't RandomAccess, then we'll need
        // to change the loop below.
        assertTrue(results instanceof RandomAccess);

        // Make sure that each of the results is what we expected.
        for (int i = 0; i < results.size(); i++)
        {
          Result<Integer, Integer> result = results.get(i);
          assertEquals(result.getInput(), Integer.valueOf(i));
          assertEquals(result.getFailureCause(), failureCause);

          if (failureCause != null)
          {
            assertEquals(result.getOutput(), null);
          }
          else
          {
            assertEquals(result.getOutput(), Integer.valueOf(i));
          }
        }
      }
    }
    finally
    {
      invoker.shutdown();
    }
  }



  /**
   * Constructs parameters for testInvalidParams.
   *
   * @return  Parameters for testInvalidParams.
   */
  @DataProvider
  public Object[][] invalidParams()
  {
    Processor<Integer,Integer> validProcessor = identityProcessor();

    return new Object[][]{
         new Object[]{ null, 1, 1 },
         new Object[]{ validProcessor, -1, 1 },
         new Object[]{ validProcessor, 1, 0 },
         new Object[]{ validProcessor, 1, -1 },
         new Object[]{ validProcessor, 1001, 1 },
    };
  }



  /**
   * Tests that the ParallelProcessor constructor properly validates the input
   * parameters.
   *
   * @param processor  The Processor to use when constructing the
   *                   ParallelProcessor.
   * @param numThreads   The number threads to use when constructing the
   *                     ParallelProcessor.
   * @param minPerThread The minimum items per thread to use when constructing
   *                     the ParallelProcessor.
   */
  @Test(dataProvider = "invalidParams",
        expectedExceptions = LDAPSDKUsageException.class)
  public void testInvalidParams(Processor<Integer, Integer> processor,
                                int numThreads, int minPerThread)
  {
    new ParallelProcessor<Integer,Integer>(processor, numThreads, minPerThread);
  }



  /**
   * Tests the ParallelProcessor#shutdown() method.
   *
   * @throws Exception  If the test failes.
   */
  @Test
  public void testShutdown()
       throws Exception
  {
    final int numInvocations = 10;
    final AtomicInteger actualInvocations = new AtomicInteger();

    final ParallelProcessor<Integer, Integer> invoker =
         new ParallelProcessor<Integer, Integer>(
              new Processor<Integer, Integer>()
              {
                @Override()
                public Integer process(Integer input)
                     throws Exception
                {
                  Thread.sleep(10);
                  actualInvocations.incrementAndGet();
                  return input;
                }
              },
              1, 1);

    final List<Integer> inputItems = rangeList(0, numInvocations);
    // We invoke the tasks in the background.
    Thread backgroundInvokerThread = new Thread()
    {
      @Override()
      public void run()
      {
        try
        {
          invoker.processAll(inputItems);
        }
        catch (InterruptedException e)
        {
          e.printStackTrace();  // This shouldn't happen.
        }
      }
    };
    backgroundInvokerThread.run();

    // Wait for the invocations to start because we want to test calling
    // shutdown while they are running.
    while (actualInvocations.get() == 0)
    {
      Thread.sleep(10);
    }

    invoker.shutdown();

    // After shutdown the input items should have been processed.
    assertEquals(actualInvocations.get(), numInvocations);

    // Another call to shutdown shouldn't throw.
    invoker.shutdown();

    // But calling invokeAll again will throw.
    try
    {
      invoker.processAll(inputItems);
      fail("Expected IllegalStateException");
    }
    catch (IllegalStateException e)
    {
      // This is expected.
    }
  }



  /**
   * Returns a Processor that returns the input value as the output.
   *
   * @return  A Processor that returns the input value as the output.
   */
  private Processor<Integer, Integer> identityProcessor()
  {
    return new Processor<Integer, Integer>()
    {
      @Override()
      public Integer process(Integer input)
           throws Exception
      {
        return input;
      }
    };
  }



  /**
   * Return a List containing (minInclusive..maxExclusive-1).
   *
   * @param minInclusive  The initial item in the returned List.
   * @param maxExclusive  The upper bound (exclusive) of the returned List.
   *
   * @return  A List containing (minInclusive..maxExclusive-1).
   */
  private static List<Integer> rangeList(int minInclusive, int maxExclusive)
  {
    List<Integer> items = new ArrayList<Integer>();
    for (int i = minInclusive; i < maxExclusive; i++)
    {
      items.add(i);
    }
    return items;
  }
}

