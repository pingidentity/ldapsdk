/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.LDAPSDKThreadFactory;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a common mechanism to do batch processing of items that
 * undergo identical processing.  It can process items in parallel using a
 * worker-thread pool while guaranteeing that the results of processAll() are
 * returned in the same order as the input list. The synchronization between the
 * threads is optimized for throughput. This class is intended to only be used
 * internally by the SDK.
 *
 * @param <I>  The type of the input items of {@code processAll}.
 * @param <O>  The type of the output items of {@code processAll}.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ParallelProcessor<I,O>
{
  /**
   * This processes the input items.  It is called in parallel by each worker
   * thread.  So it must be thread-safe.
   */
  @NotNull private final Processor<I,O> processor;

  /**
   * The work done in parallel during processAll is done by the invoking thread
   * and this pool of worker threads.
   */
  @NotNull private final List<Thread> workers;

  /**
   * When a batch of work is passed into processAll, we don't release all of the
   * worker threads all of the time.  We make sure that each one we release has
   * at least minPerThread items of work to do.  This lets us balance the effort
   * required to do the work versus the synchronization around doing the work.
   * Choosing the best value for this depends on how expensive the task is.  In
   * general, the more expensive processor.process() is, the smaller the value
   * of minPerThread.  Don't spend too much time trying to find the optimal
   * value for this.  Making the value too large is a bigger danger than having
   * it be too small.
   */
  private final int minPerThread;

  /**
   * This Semaphore is used to release the worker threads.  They are released at
   * two different times:  when there is work to do for an processAll call and
   * when the Invoker is shutdown.
   */
  @NotNull private final Semaphore workerSemaphore = new Semaphore(0);

  /**
   * This is how the Worker threads access the 'items' parameter passed into
   * invoke().
   */
  @NotNull private final AtomicReference<List<? extends I>> inputItems =
       new AtomicReference<>();

  /**
   * This is how the Worker threads return the results of processor.process()
   * back to processAll.  The list is pre-populated with null values, and the
   * Worker just sets the values.
   */
  @NotNull private final AtomicReference<List<Result<I,O>>> outputItems =
       new AtomicReference<>();

  /**
   * This is how each worker thread decides what inputItems to process. It's
   * usually more efficient then having them contend for a queue.
   */
  @NotNull private final AtomicInteger nextToProcess = new AtomicInteger();

  /**
   * When there are no more inputItems to process, each Worker thread triggers
   * this countdown latch so that the thread that called processAll knows that
   * all of the processing has completed.
   */
  @Nullable private volatile CountDownLatch processingCompleteSignal;

  /**
   * Set by shutdown() when the Invoker is shutdown.  It triggers all of the
   * Worker threads to exit.
   */
  @NotNull private final AtomicBoolean shutdown = new AtomicBoolean();



  /**
   * Constructs a new ParallelProcessor with the specified parameters.   If
   * totalThreads is greater than one, then this method will start worker
   * threads.  These worker threads will continue to run until shutdown() is
   * called.
   *
   * @param  processor     The Processor that processes the items input to
   *                       processAll.  It cannot be {@code null}.
   * @param  totalThreads  The total number of threads to use when processing
   *                       items during processAll.  This value includes the
   *                       thread that called invokeAll itself, so it cannot be
   *                       less than 1.  It also must not be more than 1000.
   * @param  minPerThread  The minimum number of items that a Worker thread has
   *                       to process during a call to processAll for it to be
   *                       released from the worker pool.  This lets us balance
   *                       the effort required to do the work versus the
   *                       synchronization around doing the work.  Choosing the
   *                       best value for this depends on how expensive the
   *                       task is.  In general, the more expensive
   *                       processor.process() is, the smaller the value of
   *                       minPerThread.  Don't spend too much time trying to
   *                       find the optimal value for this.  Making the value
   *                       too large is a bigger danger than having it be too
   *                       small.
   */
  public ParallelProcessor(@NotNull final Processor<I,O> processor,
                           final int totalThreads,
                           final int minPerThread)
  {
    this(processor, null, totalThreads, minPerThread);
  }



  /**
   * Constructs a new ParallelProcessor with the specified parameters.   If
   * totalThreads is greater than one, then this method will start worker
   * threads.  These worker threads will continue to run until shutdown() is
   * called.
   *
   * @param  processor      The Processor that processes the items input to
   *                        processAll.  It cannot be {@code null}.
   * @param  threadFactory  The thread factory that should be used for creating
   *                        worker threads.  It may be {@code null} if a default
   *                        thread factory should be used.
   * @param  totalThreads   The total number of threads to use when processing
   *                        items during processAll.  This value includes the
   *                        thread that called invokeAll itself, so it cannot be
   *                        less than 1.  It also must not be more than 1000.
   * @param  minPerThread   The minimum number of items that a Worker thread has
   *                        to process during a call to processAll for it to be
   *                        released from the worker pool.  This lets us balance
   *                        the effort required to do the work versus the
   *                        synchronization around doing the work.  Choosing the
   *                        best value for this depends on how expensive the
   *                        task is.  In general, the more expensive
   *                        processor.process() is, the smaller the value of
   *                        minPerThread.  Don't spend too much time trying to
   *                        find the optimal value for this.  Making the value
   *                        too large is a bigger danger than having it be too
   *                        small.
   */
  public ParallelProcessor(@NotNull final Processor<I,O> processor,
                           @Nullable final ThreadFactory threadFactory,
                           final int totalThreads,
                           final int minPerThread)
  {
    Validator.ensureNotNull(processor);
    Validator.ensureTrue(totalThreads >= 1,
         "ParallelProcessor.totalThreads must be at least 1.");
    Validator.ensureTrue(totalThreads <= 1000,  // Upper bound on # of threads
         "ParallelProcessor.totalThreads must not be greater than 1000.");
    Validator.ensureTrue(minPerThread >= 1,
         "ParallelProcessor.minPerThread must be at least 1.");

    this.processor = processor;
    this.minPerThread = minPerThread;

    final ThreadFactory tf;
    if (threadFactory == null)
    {
      tf = new LDAPSDKThreadFactory("ParallelProcessor-Worker", true);
    }
    else
    {
      tf = threadFactory;
    }

    final int numExtraThreads = totalThreads - 1;
    final List<Thread> workerList = new ArrayList<>(numExtraThreads);
    for (int i = 0; i < numExtraThreads; i++)
    {
      final Thread worker = tf.newThread(new Worker());
      workerList.add(worker);
      worker.start();
    }
    workers = workerList;
  }



  /**
   * Processes items (possibly in parallel and out-of-order) and returns the
   * result of the processing.
   *
   * @param items The items to process in parallel.  It must not be {@code
   *              null}.
   *
   * @return The results of calling processor.process() on each item in the
   *         input items list.  This List will have exactly one item for each
   *         item in the input {@code items} array at the same corresponding
   *         position as the input items.
   *
   * @throws InterruptedException  If this thread is interrupted during
   *                               processing.
   * @throws IllegalStateException If this thread is called after shutdown().
   */
  @NotNull()
  public synchronized ArrayList<Result<I,O>> processAll(
              @NotNull final List<? extends I> items)
         throws InterruptedException, IllegalStateException
  {
    if (shutdown.get())
    {
      throw new IllegalStateException(
           "cannot call processAll() after shutdown()");
    }
    Validator.ensureNotNull(items);

    // When there isn't a lot of work to do, it's normally more efficient to
    // have fewer threads do the work when each work item is small, so figure
    // out how many threads we need based on the minimum amount of work that
    // each thread should do.  Also, subtract 1 to account for this thread,
    // which will also participate.
    final int extraThreads =
         Math.min((items.size() / minPerThread) - 1, workers.size());

    // Process everything in this thread.
    if (extraThreads <= 0)
    {
      final ArrayList<Result<I,O>> output = new ArrayList<>(items.size());
      for (final I item : items)
      {
        output.add(process(item));
      }
      return output;
    }

    processingCompleteSignal = new CountDownLatch(extraThreads);

    inputItems.set(items);

    // Pre-populate the output List with null values so that the results can
    // be set out-of-order by the individual threads by calling
    // List#set(index, value)
    final ArrayList<Result<I,O>> output = new ArrayList<>(items.size());
    for (int i = 0; i < items.size(); i++)
    {
      output.add(null); // So we can just call set later
    }

    outputItems.set(output);
    nextToProcess.set(0);

    workerSemaphore.release(extraThreads);

    // This thread does its part toward completing the work.
    processInParallel();

    // Even though there is no more work for this thread to do, all of the other
    // threads might not have finished yet, so we must wait for them.
    processingCompleteSignal.await();

    return output;
  }



  /**
   * Shuts this down.  This includes waiting for all worker threads to finish.
   * It is not an error to call shutdown() more than once, but it is an error to
   * call processAll() after shutdown() has been called.
   *
   * @throws InterruptedException If this thread is interrupted during
   *                              processing.
   */
  public synchronized void shutdown()
       throws InterruptedException
  {
    if (shutdown.getAndSet(true))
    {
      // Already shut down.
      return;
    }

    workerSemaphore.release(workers.size());

    for (final Thread worker : workers)
    {
      worker.join();
    }
  }



  /**
   * Processes inputItems (along with other threads) until there are no more
   * free items to process.
   */
  private void processInParallel()
  {
    try
    {
      final List<? extends I> items = inputItems.get();
      final List<Result<I,O>> outputs = outputItems.get();
      final int size = items.size();
      int next;
      while ((next = nextToProcess.getAndIncrement()) < size)
      {
        final I input = items.get(next);
        outputs.set(next, process(input));
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      // As with catching InterruptedException above, it's bad if this
      // thread throws an unchecked exception because it can deadlock other
      // threads.  So we keep on processing even if there is an Exception.
      // This is very unlikely because there is nothing above that should
      // throw especially since the process() method itself catches Exception.
    }
  }



  /**
   * Processes a single item.
   *
   * @param input The input item to process.
   *
   * @return The result of the processing.
   */
  @NotNull()
  private ProcessResult process(@NotNull final I input)
  {
    O output = null;
    Throwable failureCause = null;

    try
    {
      output = processor.process(input);
    }
    catch (final Throwable e)
    {
      failureCause = e;
    }

    return new ProcessResult(input, output, failureCause);
  }



  /**
   * Internal worker thread class.
   */
  private final class Worker
          implements Runnable
  {
    /**
     * Creates a new worker instance.
     */
    private Worker()
    {
    }



    /**
     * Iteratively process batches of work passed in to processAll until
     * shutdown.
     */
    @Override()
    public void run()
    {
      while (true)
      {
        try
        {
          // This thread will acquire the semaphore in only two situations.
          //  1) it was released by processAll
          //  2) it was released by shutdown
          workerSemaphore.acquire();
        }
        catch (final InterruptedException e)
        {
          Debug.debugException(e);
          // It's not good practice to eat an InterruptedException, but it's
          // also not good practice to interrupt threads that you don't own.
          // It's dangerous if this thread exits prematurely because it can
          // cause other dependent threads to block when there's no thread
          // left to do the work.
          Thread.currentThread().interrupt();
        }

        if (shutdown.get())
        {
          return;
        }

        try
        {
          processInParallel();
        }
        finally
        {
          // Signals to the thread that called processAll that this thread
          // has finished processing this batch.
          processingCompleteSignal.countDown();
        }
      }
    }
  }



  /**
   * Result of processing a single item.
   */
  private final class ProcessResult
       implements Result<I,O>
  {
    // The item that was passed into processAll.
    @NotNull private final I inputItem;

    // The result of calling processor#process().  This will always be null
    // if failureCause is set.
    @Nullable private final O outputItem;

    // If processor#process() throws an Exception, it is set here.
    @Nullable private final Throwable failureCause;



    /**
     * Constructor.
     *
     * @param inputItem    The item that was passed into processAll.
     * @param outputItem   The result of calling processor#process().  This will
     *                     always be null if failureCause is set.
     * @param failureCause If processor#process() throws an Exception, it is set
     *                     here.
     */
    private ProcessResult(@NotNull final I inputItem,
                          @Nullable final O outputItem,
                          @Nullable final Throwable failureCause)
    {
      this.inputItem = inputItem;
      this.outputItem = outputItem;
      this.failureCause = failureCause;
    }



    /**
     * {@inheritDoc}
     */
    @Override()
    @NotNull()
    public I getInput()
    {
      return inputItem;
    }



    /**
     * {@inheritDoc}
     */
    @Override()
    @Nullable()
    public O getOutput()
    {
      return outputItem;
    }



    /**
     * {@inheritDoc}
     */
    @Override()
    @Nullable()
    public Throwable getFailureCause()
    {
      return failureCause;
    }
  }
}
