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



import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ArrayBlockingQueue;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.util.NotNull;
import com.unboundid.util.UtilTestCase;



/**
 * Tests for AsynchronousParallelProcessor.
 */
public class AsynchronousParallelProcessorTestCase
     extends UtilTestCase
{

  /**
   * Returns parameters for testBasics().
   *
   * @return  Parameters for testBasics().
   */
  @DataProvider
  public Object[][] basicsParams()
  {
    return new Object[][]{
            new Object[]{1, 1,   10,                       null, 1000, 1000},
            new Object[]{2, 4,  100,                       null, 1000, 1000},
            new Object[]{8, 1, 1000,                       null, 1000, 1000},

            new Object[]{1, 1,   10,       new AssertionError(), 1000, 1000},
            new Object[]{1, 1,   10,     new RuntimeException(), 1000, 1000},
            new Object[]{2, 4,  100, new InterruptedException(), 1000, 1000},
            new Object[]{8, 1, 1000,            new Throwable(), 1000, 1000},

            new Object[]{1, 1,   10,                       null, 1000,    1},
            new Object[]{2, 4,  100,                       null, 1000,    1},
            new Object[]{8, 1, 1000,                       null, 1000,    1},

            new Object[]{1, 1,   10,                       null,    1, 1000},
            new Object[]{2, 4,  100,                       null,    1, 1000},
            new Object[]{8, 1, 1000,                       null,    1, 1000},

            new Object[]{1, 1,   10,                       null,    1,    1},
            new Object[]{2, 4,  100,                       null,    1,    1},
            new Object[]{8, 1, 1000,                       null,    1,    1},
    };
  }



  /**
   * Tests basic operation of the AsynchronousParallelProcessor class.
   *
   * @param numThreads  The number of threads to use for the ParallelProcessor.
   * @param minPerThread  Minimum number of work items per thread.
   * @param numItems  The number of items to submit for processing.
   * @param failureCause  Non-null if processing should fail with this cause.
   * @param inputQueueSize  The input queue capacity.
   * @param outputQueueSize  The output queue capacity.
   *
   * @throws Exception  If the test fails.
   */
  @Test(dataProvider = "basicsParams")
  public void testBasics(final int numThreads,
                         final int minPerThread,
                         final int numItems,
                         final Throwable failureCause,
                         final int inputQueueSize,
                         final int outputQueueSize)
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

    BlockingQueue<Integer> inputQueue =
         new ArrayBlockingQueue<Integer>(inputQueueSize);

    BlockingQueue<Result<Integer, Integer>> outputQueue =
         new ArrayBlockingQueue<Result<Integer, Integer>>(outputQueueSize);


    final AsynchronousParallelProcessor<Integer, Integer> asyncInvoker =
         new AsynchronousParallelProcessor<Integer, Integer>(inputQueue,
                                                             invoker,
                                                             outputQueue);

    // Submit all of the items in the background
    Thread submitInBackgroundThread = new Thread()
    {
      @Override()
      public void run()
      {
        try
        {
          for (int i = 0; i < numItems; i++)
          {
            asyncInvoker.submit(i);
          }
        }
        catch (Exception e)
        {
          e.printStackTrace();  // This shouldn't happen.
        }
      }
    };
    submitInBackgroundThread.start();

    // Check the results
    for (int i = 0; i < numItems; i++)
    {
      Result<Integer, Integer> result = outputQueue.take();

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

    submitInBackgroundThread.join();

    asyncInvoker.shutdown();

    // Shutting down again shouldn't have any affect.
    asyncInvoker.shutdown();

    // But trying to submit another item should throw IllegalStateException.
    try
    {
      asyncInvoker.submit(0);
      fail("Expected IllegalStateException");
    }
    catch (IllegalStateException e)
    {
      // This is expected.
    }
  }



  /**
   * Test that a failure in the ResultProcessor is handled properly.
   *
   * @throws Exception  If the test fails.
   */
  @Test
  public void testResultProcessorException()
       throws Exception
  {
    Processor<Integer, Integer> processor = new Processor<Integer, Integer>()
    {
      @Override()
      public Integer process(Integer input)
           throws Throwable
      {
        return input;
      }
    };

    ParallelProcessor<Integer, Integer> invoker =
         new ParallelProcessor<Integer, Integer>(
              processor, 2, 1);

    BlockingQueue<Integer> inputQueue =
         new ArrayBlockingQueue<Integer>(10);


    final Exception injectedFailure = new Exception();

    final AsynchronousParallelProcessor<Integer, Integer> asyncInvoker =
         new AsynchronousParallelProcessor<Integer, Integer>(
              inputQueue,
              invoker,
              // This ResultProcessor will throw every time.
              new ResultProcessor<Integer, Integer>()
              {
                @Override()
                public void processResult(
                     @NotNull Result<Integer, Integer> integerIntegerResult)
                     throws Exception
                {
                  throw injectedFailure;
                }
              });

    // This will trigger an error in the result processor.
    asyncInvoker.submit(1);

    // Eventually the result processor will run and we should get an error here.
    boolean exceptionCaught = false;
    for (int i = 0; i < 1000; i++)
    {
      try
      {
        asyncInvoker.submit(0);
      }
      catch (RuntimeException e)
      {
        assertEquals(e.getCause(), injectedFailure, e.toString());
        exceptionCaught = true;
        break;
      }
      Thread.sleep(10);
    }

    assertTrue(exceptionCaught);

    asyncInvoker.shutdown();
  }
}
