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
package com.unboundid.ldap.sdk.examples;



import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.util.Debug;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ResultCodeCounter;
import com.unboundid.util.ValuePattern;



/**
 * This class provides a thread that may be used to repeatedly perform
 * modifications.
 */
final class ModRateThread
      extends Thread
{
  // Indicates whether a request has been made to stop running.
  @NotNull private final AtomicBoolean stopRequested;

  // The number of modrate threads that are currently running.
  @NotNull private final AtomicInteger runningThreads;

  // The counter used to track the number of errors encountered while
  // processing modifications.
  @NotNull private final AtomicLong errorCounter;

  // The counter used to track the number of modifications performed.
  @NotNull private final AtomicLong modCounter;

  // The value that will be updated with total duration of the modifications.
  @NotNull private final AtomicLong modDurations;

  // The counter used to track the number of iterations remaining on the
  // current connection.
  @Nullable private final AtomicLong remainingIterationsBeforeReconnect;

  // The result code for this thread.
  @NotNull private final AtomicReference<ResultCode> resultCode;

  // Indicates whether to generate increment modifications instead of replace
  // modifications.
  private final boolean increment;

  // The set of request controls to include in modify requests.
  @NotNull private final Control[] modifyControls;

  // The barrier that will be used to coordinate starting among all the threads.
  @NotNull private final CyclicBarrier startBarrier;

  // The barrier to use for controlling the rate of modifies.  null if no
  // rate-limiting should be used.
  @Nullable private final FixedRateBarrier fixedRateBarrier;

  // The amount by which to increment values.
  private final int incrementAmount;

  // The number of values to generate.
  private final int valueCount;

  // The connection to use for the modifications.
  @Nullable private LDAPConnection connection;

  // The number of iterations to request on a connection before closing and
  // re-establishing it.
  private final long iterationsBeforeReconnect;

  // A reference to the associated modrate tool that can be used when attempting
  // to establish connections.
  @NotNull private final ModRate modRate;

  // The result code counter to use for failed operations.
  @NotNull private final ResultCodeCounter rcCounter;

  // The names of the attributes to modify.
  @NotNull private final String[] attributes;

  // The thread that is actually performing the modifications.
  @NotNull private final AtomicReference<Thread> modThread;

  // The value pattern to use for proxied authorization.
  @Nullable private final ValuePattern authzID;

  // The value pattern to use for the entry DNs.
  @NotNull private final ValuePattern entryDN;

  // The value pattern to use to generate values.
  @NotNull private final ValuePattern valuePattern;



  /**
   * Creates a new mod rate thread with the provided information.
   *
   * @param  modRate                    A reference to the associated modrate
   *                                    tool.
   * @param  threadNumber               The thread number for this thread.
   * @param  connection                 The connection to use for the
   *                                    modifications.
   * @param  entryDN                    The value pattern to use for the entry
   *                                    DNs.
   * @param  attributes                 The names of the attributes to modify.
   * @param  valuePattern               The pattern to use to generate values.
   * @param  valueCount                 The number of values to generate for
   *                                    replace modifications.
   * @param  increment                  Indicates whether to use the increment
   *                                    modification type instead of the replace
   *                                    modification type.
   * @param  incrementAmount            The amount by which values should be
   *                                    incremented.
   * @param  modifyControls             The set of request controls that should
   *                                    be included in modify requests.
   * @param  authzID                    The value pattern to use to generate
   *                                    authorization identities for use with
   *                                    the proxied authorization control.  It
   *                                    may be {@code null} if proxied
   *                                    authorization should not be used.
   * @param  iterationsBeforeReconnect  The number of iterations that should be
   *                                    processed on a connection before it is
   *                                    closed and replaced with a
   *                                    newly-established connection.
   * @param  runningThreads             An atomic integer that will be
   *                                    incremented when this thread starts,
   *                                    and decremented when it completes.
   * @param  startBarrier               A barrier used to coordinate starting
   *                                    between all of the threads.
   * @param  modCounter                 A value that will be used to keep track
   *                                    of the total number of modifications
   *                                    performed.
   * @param  modDurations               A value that will be used to keep track
   *                                    of the total duration for all
   *                                    modifications.
   * @param  errorCounter               A value that will be used to keep track
   *                                    of the number of errors encountered
   *                                    while processing.
   * @param  rcCounter                  The result code counter to use for
   *                                    keeping track of the result codes for
   *                                    failed operations.
   * @param  rateBarrier                The barrier to use for controlling the
   *                                    rate of modifies.  {@code null} if no
   *                                    rate-limiting should be used.
   */
  ModRateThread(@NotNull final ModRate modRate, final int threadNumber,
                @NotNull final LDAPConnection connection,
                @NotNull final ValuePattern entryDN,
                @NotNull final String[] attributes,
                @NotNull final ValuePattern valuePattern,
                final int valueCount, final boolean increment,
                final int incrementAmount,
                @NotNull final Control[] modifyControls,
                @Nullable final ValuePattern authzID,
                final long iterationsBeforeReconnect,
                @NotNull final AtomicInteger runningThreads,
                @NotNull final CyclicBarrier startBarrier,
                @NotNull final AtomicLong modCounter,
                @NotNull final AtomicLong modDurations,
                @NotNull final AtomicLong errorCounter,
                @NotNull final ResultCodeCounter rcCounter,
                @Nullable final FixedRateBarrier rateBarrier)
  {
    setName("ModRate Thread " + threadNumber);
    setDaemon(true);

    this.modRate                   = modRate;
    this.connection                = connection;
    this.entryDN                   = entryDN;
    this.attributes                = attributes;
    this.valuePattern              = valuePattern;
    this.valueCount                = valueCount;
    this.increment                 = increment;
    this.incrementAmount           = incrementAmount;
    this.modifyControls            = modifyControls;
    this.authzID                   = authzID;
    this.iterationsBeforeReconnect = iterationsBeforeReconnect;
    this.modCounter                = modCounter;
    this.modDurations              = modDurations;
    this.errorCounter              = errorCounter;
    this.rcCounter                 = rcCounter;
    this.runningThreads            = runningThreads;
    this.startBarrier              = startBarrier;
    fixedRateBarrier               = rateBarrier;

    if (iterationsBeforeReconnect > 0L)
    {
      remainingIterationsBeforeReconnect =
           new AtomicLong(iterationsBeforeReconnect);
    }
    else
    {
      remainingIterationsBeforeReconnect = null;
    }

    connection.setConnectionName("mod-" + threadNumber);

    resultCode    = new AtomicReference<>(null);
    modThread     = new AtomicReference<>(null);
    stopRequested = new AtomicBoolean(false);
  }



  /**
   * Performs all modify processing for this thread.
   */
  @Override()
  public void run()
  {
    try
    {
      modThread.set(currentThread());
      runningThreads.incrementAndGet();

      final Modification[] mods = new Modification[attributes.length];
      final String[] values = new String[valueCount];

      if (increment)
      {
        values[0] = String.valueOf(incrementAmount);

        for (int i=0; i < attributes.length; i++)
        {
          mods[i] = new Modification(ModificationType.INCREMENT, attributes[i],
               values);
        }
      }

      final ModifyRequest modifyRequest = new ModifyRequest("", mods);

      try
      {
        startBarrier.await();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      while (! stopRequested.get())
      {
        if ((iterationsBeforeReconnect > 0L) &&
             (remainingIterationsBeforeReconnect.decrementAndGet() <= 0))
        {
          remainingIterationsBeforeReconnect.set(iterationsBeforeReconnect);
          if (connection != null)
          {
            connection.close();
            connection = null;
          }
        }

        if (connection == null)
        {
          try
          {
            connection = modRate.getConnection();
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);

            errorCounter.incrementAndGet();

            final ResultCode rc = le.getResultCode();
            rcCounter.increment(rc);
            resultCode.compareAndSet(null, rc);

            if (fixedRateBarrier != null)
            {
              fixedRateBarrier.await();
            }

            continue;
          }
        }

        modifyRequest.setDN(entryDN.nextValue());

        if (! increment)
        {
          for (int i=0; i < valueCount; i++)
          {
            values[i] = valuePattern.nextValue();
          }

          for (int i=0; i < attributes.length; i++)
          {
            mods[i] = new Modification(ModificationType.REPLACE, attributes[i],
                 values);
          }
          modifyRequest.setModifications(mods);
        }

        modifyRequest.setControls(modifyControls);
        if (authzID != null)
        {
          modifyRequest.addControl(new ProxiedAuthorizationV2RequestControl(
               authzID.nextValue()));
        }


        // If we're trying for a specific target rate, then we might need to
        // wait until issuing the next modify.
        if (fixedRateBarrier != null)
        {
          fixedRateBarrier.await();
        }

        final long startTime = System.nanoTime();
        try
        {
          connection.modify(modifyRequest);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          errorCounter.incrementAndGet();

          final ResultCode rc = le.getResultCode();
          rcCounter.increment(rc);
          resultCode.compareAndSet(null, rc);

          if (! le.getResultCode().isConnectionUsable())
          {
            connection.close();
            connection = null;
          }
        }

        modCounter.incrementAndGet();
        modDurations.addAndGet(System.nanoTime() - startTime);
      }
    }
    finally
    {
      if (connection != null)
      {
        connection.close();
      }

      modThread.set(null);
      runningThreads.decrementAndGet();
    }
  }



  /**
   * Indicates that this thread should stop running.
   *
   * @return  A result code that provides information about whether any errors
   *          were encountered during processing.
   */
  @NotNull()
  public ResultCode stopRunning()
  {
    final Thread t = modThread.get();
    stopRequested.set(true);

    if (fixedRateBarrier != null)
    {
      fixedRateBarrier.shutdownRequested();
    }

    if (t != null)
    {
      try
      {
        t.join();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (e instanceof InterruptedException)
        {
          Thread.currentThread().interrupt();
        }
      }
    }

    resultCode.compareAndSet(null, ResultCode.SUCCESS);
    return resultCode.get();
  }
}
