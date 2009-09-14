/*
 * Copyright 2008-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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



import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.ValuePattern;



/**
 * This class provides a thread that may be used to repeatedly perform
 * modifications.
 */
final class ModRateThread
      extends Thread
{
  // Indicates whether a request has been made to start running.
  private final AtomicBoolean startRequested;

  // Indicates whether a request has been made to stop running.
  private final AtomicBoolean stopRequested;

  // The counter used to track the number of errors encountered while
  // processing modifications.
  private final AtomicLong errorCounter;

  // The counter used to track the number of modifications performed.
  private final AtomicLong modCounter;

  // The value that will be updated with total duration of the modifications.
  private final AtomicLong modDurations;

  // The set of characters to use for the generated values.
  private final byte[] charSet;

  // The length in bytes of the values to generate.
  private final int valueLength;

  // The connection to use for the modifications.
  private final LDAPConnection connection;

  // The random number generator to use for this thread.
  private final Random random;

  // The result code for this thread.
  private final AtomicReference<ResultCode> resultCode;

  // The names of the attributes to modify.
  private final String[] attributes;

  // The thread that is actually performing the modifications.
  private final AtomicReference<Thread> modThread;

  // The value pattern to use for the entry DNs.
  private final ValuePattern entryDN;

  // The barrier to use for controlling the rate of modifies.  null if no
  // rate-limiting should be used.
  private final FixedRateBarrier fixedRateBarrier;



  /**
   * Creates a new mod rate thread with the provided information.
   *
   * @param  threadNumber  The thread number for this thread.
   * @param  connection    The connection to use for the modifications.
   * @param  entryDN       The value pattern to use for the entry DNs.
   * @param  attributes    The names of the attributes to modify.
   * @param  charSet       The set of characters to include in the generated
   *                       values.
   * @param  valueLength   The length in bytes to use for the generated values.
   * @param  randomSeed    The seed to use for the random number generator.
   * @param  shouldStart   Indicates whether the thread should actually start
   *                       running.
   * @param  modCounter    A value that will be used to keep track of the total
   *                       number of modifications performed.
   * @param  modDurations  A value that will be used to keep track of the total
   *                       duration for all modifications.
   * @param  errorCounter  A value that will be used to keep track of the number
   *                       of errors encountered while processing.
   * @param  rateBarrier   The barrier to use for controlling the rate of
   *                       modifies.  {@code null} if no rate-limiting
   *                       should be used.
   */
  ModRateThread(final int threadNumber, final LDAPConnection connection,
                final ValuePattern entryDN, final String[] attributes,
                final byte[] charSet, final int valueLength,
                final long randomSeed, final AtomicBoolean shouldStart,
                final AtomicLong modCounter, final AtomicLong modDurations,
                final AtomicLong errorCounter,
                final FixedRateBarrier rateBarrier)
  {
    setName("ModRate Thread " + threadNumber);
    setDaemon(true);

    this.connection   = connection;
    this.entryDN      = entryDN;
    this.attributes   = attributes;
    this.charSet      = charSet;
    this.valueLength  = valueLength;
    this.modCounter   = modCounter;
    this.modDurations = modDurations;
    this.errorCounter = errorCounter;
    startRequested    = shouldStart;
    fixedRateBarrier  = rateBarrier;

    connection.setConnectionName("mod-" + threadNumber);

    resultCode    = new AtomicReference<ResultCode>(null);
    modThread     = new AtomicReference<Thread>(null);
    stopRequested = new AtomicBoolean(false);
    random        = new Random(randomSeed);
  }



  /**
   * Performs all modify processing for this thread.
   */
  @Override()
  public void run()
  {
    modThread.set(currentThread());

    final Modification[] mods = new Modification[attributes.length];
    final byte[] valueBytes = new byte[valueLength];
    final ASN1OctetString[] values = new ASN1OctetString[1];

    while (! startRequested.get())
    {
      yield();
    }

    while (! stopRequested.get())
    {
      for (int i=0; i < valueLength; i++)
      {
        valueBytes[i] = charSet[random.nextInt(charSet.length)];
      }

      values[0] = new ASN1OctetString(valueBytes);
      for (int i=0; i < attributes.length; i++)
      {
        mods[i] = new Modification(ModificationType.REPLACE, attributes[i],
                                   values);
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
        connection.modify(entryDN.nextValue(), mods);
      }
      catch (LDAPException le)
      {
        errorCounter.incrementAndGet();
        resultCode.compareAndSet(null, le.getResultCode());
      }

      modCounter.incrementAndGet();
      modDurations.addAndGet(System.nanoTime() - startTime);
    }

    connection.close();
    modThread.set(null);
  }



  /**
   * Indicates that this thread should stop running.
   *
   * @return  A result code that provides information about whether any errors
   *          were encountered during processing.
   */
  public ResultCode stopRunning()
  {
    stopRequested.set(true);

    if (fixedRateBarrier != null)
    {
      fixedRateBarrier.shutdownRequested();
    }

    final Thread t = modThread.get();
    if (t != null)
    {
      try
      {
        t.join();
      } catch (Exception e) {}
    }

    resultCode.compareAndSet(null, ResultCode.SUCCESS);
    return resultCode.get();
  }
}
