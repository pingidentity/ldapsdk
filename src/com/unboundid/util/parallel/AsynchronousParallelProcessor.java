/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an asynchronous mechanism to do parallel processing of
 * items that undergo identical processing.  It can be used as part of a
 * pipeline where input items are submitted without waiting for them to
 * complete.  To prevent a backlog of input or output items, a maximum
 * capacity should be set on the {@code pendingQueue} and {@code outputQueue}
 * if one is used.
 * <p/>
 * The {@link ParallelProcessor} passed into the constructor is wholly owned
 * by this instance.  It should not be used elsewhere after constructing this
 * instance.  It will be shut down when this instance's {@code shutdown()}
 * method is called.
 * <p/>
 * When this AsynchronousParallelProcessor is no longer needed, {@code shutdown}
 * must be called to terminate all worker threads.
 * <p/>
 * This class is intended to only be used internally by the SDK.
 *
 * @param <I>  The type of the input items of {@code processAll}.
 * @param <O>  The type of the output items of {@code processAll}.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AsynchronousParallelProcessor<I, O>
{

  // Queue of input items.
  private final BlockingQueue<I> pendingQueue;

  // The ParallelProcessor that is used to process the input items.
  private final ParallelProcessor<I, O> parallelProcessor;

  // Processor for the results.
  private final ResultProcessor<I, O> resultProcessor;

  // Thread that pulls items from pendingQueue, passes them to
  // parallelProcessor, and processes the results.
  private final InvokerThread invokerThread;

  // Set to true when this is shutdown.
  private final AtomicBoolean shutdown = new AtomicBoolean(false);

  // Set by worker threads to signal that there was a problem during processing.
  // Once this is set, all calls to submit() will fail with this exception.
  private final AtomicReference<Throwable> invocationException =
       new AtomicReference<Throwable>();



  /**
   * Constructs a new AsynchronousParallelProcessor with the specified
   * parameters.
   *
   * @param pendingQueue  The queue where pending input items will be stored.
   *                      If processing of input items cannot keep up with the
   *                      rate that they are submitted, then this queue can grow
   *                      without bound unless it was created with a maximum
   *                      capacity.  This queue must be used exclusively by this
   *                      instance.
   * @param parallelProcessor  The ParallelProcessor that is used to process
   *                           the submitted input items.  It must be used
   *                           exclusively by this instance.  When this instance
   *                           is shutdown, the ParallelProcessor will be
   *                           shutdown too.
   * @param resultProcessor  The ResultProcessor that is invoked sequentially
   *                         for each result.
   */
  public AsynchronousParallelProcessor(
       final BlockingQueue<I> pendingQueue,
       final ParallelProcessor<I, O> parallelProcessor,
       final ResultProcessor<I, O> resultProcessor)
  {
    this.pendingQueue = pendingQueue;
    this.parallelProcessor = parallelProcessor;
    this.resultProcessor = resultProcessor;

    this.invokerThread = new InvokerThread();
    this.invokerThread.start();
  }



  /**
   * Constructs a new AsynchronousParallelProcessor with the specified
   * parameters.
   *
   * @param pendingQueue  The queue where pending input items will be stored.
   *                      If processing of input items cannot keep up with the
   *                      rate that they are submitted, then this queue can grow
   *                      without bound unless it was created with a maximum
   *                      capacity.  This queue must be used exclusively by this
   *                      instance.
   * @param parallelProcessor  The ParallelProcessor that is used to process
   *                           the submitted input items.  It must be used
   *                           exclusively by this instance.  When this instance
   *                           is shutdown, the ParallelProcessor will be
   *                           shutdown too.
   * @param outputQueue  The output queue where results will be submitted
   *                     sequentially in the order that they were submitted.
   *                     If the queue has maximum capacity, then processing
   *                     will cease while waiting for capacity in the queue.
   */
  public AsynchronousParallelProcessor(
       final BlockingQueue<I> pendingQueue,
       final ParallelProcessor<I, O> parallelProcessor,
       final BlockingQueue<Result<I, O>> outputQueue)
  {
    this(pendingQueue, parallelProcessor,
         new OutputEnqueuer<I, O>(outputQueue));
  }



  /**
   * Submits the specified item for processing, waiting if necessary for
   * room in the pendingQueue.
   *
   * @param input  The input item to process.  It must not be {@code null}.
   *
   * @throws InterruptedException  If this thread is interrupted during
   *                               processing.
   */
  public synchronized void submit(final I input)
       throws InterruptedException
  {
    if (shutdown.get())
    {
      throw new IllegalStateException("cannot call submit() after shutdown()");
    }

    final Throwable resultProcessingError = invocationException.get();
    if (resultProcessingError != null)
    {
      shutdown();
      throw new RuntimeException(resultProcessingError);
    }

    pendingQueue.put(input);
  }



  /**
   * Shuts this down.  This includes waiting for all worker threads to
   * finish.  Processing of all input items will complete before this call
   * returns.  It is not an error to call {@code shutdown()} more than once,
   * but it is an error to call {@code submit()} after {@code shutdown()} has
   * been called.
   *
   * @throws InterruptedException  If this thread is interrupted during
   *                               processing.
   */
  public synchronized void shutdown()
       throws InterruptedException
  {
    if (shutdown.getAndSet(true))
    {
      // Already shut down.
      return;
    }

    // The invoker thread will not exit until it has completed all
    // of the pending items.
    invokerThread.join();

    parallelProcessor.shutdown();
  }



  /**
   * ResultProcessor implementation that enqueues results.
   *
   * @param <I>  The type of the input items of {@code processAll}.
   * @param <O>  The type of the output items of {@code processAll}.
   */
  private static final class OutputEnqueuer<I, O>
       implements ResultProcessor<I, O>
  {
    private final BlockingQueue<Result<I, O>> outputQueue;



    /**
     * Constructor.
     *
     * @param outputQueue  The queue where results will be enqueued.
     */
    private OutputEnqueuer(final BlockingQueue<Result<I, O>> outputQueue)
    {
      this.outputQueue = outputQueue;
    }


    /**
     * {@inheritDoc}
     */
    @Override()
    public void processResult(final Result<I, O> ioResult)
         throws Exception
    {
      outputQueue.put(ioResult);
    }
  }


  /**
   * This thread pulls items from pendingQueue, processes them in parallel,
   * and passes the results to resultProcessor.  And then does it all over again
   * until it's shutdown and there is no more to process.
   */
  private final class InvokerThread
       extends Thread
  {
    /**
     * Constructor.
     */
    private InvokerThread()
    {
      super("Asynchronous Parallel Processor");
      setDaemon(true);
    }



    /**
     * Pulls items from pendingQueue, processes them in parallel,
     * and passes the results to resultProcessor.  And then does it all over
     * again until it's shutdown and there is no more to process.
     */
    @Override()
    public void run()
    {
      while (!(shutdown.get() && pendingQueue.isEmpty()))
      {
        try
        {
          final I item = pendingQueue.poll(100, TimeUnit.MILLISECONDS);
          if (item != null)
          {
            final List<I> items = new ArrayList<I>(1 + pendingQueue.size());
            items.add(item);
            pendingQueue.drainTo(items);

            final List<Result<I, O>> results =
                 parallelProcessor.processAll(items);

            for (final Result<I, O> result : results)
            {
              resultProcessor.processResult(result);
            }
          }
        }
        catch (final Throwable e)
        {
          Debug.debugException(e);

          // It's in the contract of this class that nothing in this try
          // block should throw an exception under normal operating conditions.
          // So if we ever catch something here, then we treat that it as
          // a terminating condition.  This thread will continue to run to
          // drain any remaining items from the queue, so that we can shutdown
          // reasonably cleanly.  However, we will not accept any new input
          // item submissions.  That is, future calls to submit() will force
          // a shutdown and then throw an Exception, which includes e as the
          // original cause.  We use compareAndSet so that we only keep track
          // of the first caught exception.

          invocationException.compareAndSet(null, e);
        }
      }
    }
  }
}
