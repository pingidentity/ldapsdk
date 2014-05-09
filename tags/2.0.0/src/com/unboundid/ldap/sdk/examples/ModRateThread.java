/*
 * Copyright 2008-2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2010 UnboundID Corp.
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
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.util.FixedRateBarrier;
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
  private final AtomicBoolean stopRequested;

  // The counter used to track the number of errors encountered while
  // processing modifications.
  private final AtomicLong errorCounter;

  // The counter used to track the number of modifications performed.
  private final AtomicLong modCounter;

  // The value that will be updated with total duration of the modifications.
  private final AtomicLong modDurations;

  // The result code for this thread.
  private final AtomicReference<ResultCode> resultCode;

  // The set of characters to use for the generated values.
  private final byte[] charSet;

  // The barrier that will be used to coordinate starting among all the threads.
  private final CyclicBarrier startBarrier;

  // The length in bytes of the values to generate.
  private final int valueLength;

  // The connection to use for the modifications.
  private final LDAPConnection connection;

  // The result code counter to use for failed operations.
  private final ResultCodeCounter rcCounter;

  // The random number generator to use for this thread.
  private final Random random;

  // The names of the attributes to modify.
  private final String[] attributes;

  // The thread that is actually performing the modifications.
  private final AtomicReference<Thread> modThread;

  // The value pattern to use for proxied authorization.
  private final ValuePattern authzID;

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
   * @param  authzID       The value pattern to use to generate authorization
   *                       identities for use with the proxied authorization
   *                       control.  It may be {@code null} if proxied
   *                       authorization should not be used.
   * @param  randomSeed    The seed to use for the random number generator.
   * @param  startBarrier  A barrier used to coordinate starting between all of
   *                       the threads.
   * @param  modCounter    A value that will be used to keep track of the total
   *                       number of modifications performed.
   * @param  modDurations  A value that will be used to keep track of the total
   *                       duration for all modifications.
   * @param  errorCounter  A value that will be used to keep track of the number
   *                       of errors encountered while processing.
   * @param  rcCounter     The result code counter to use for keeping track
   *                       of the result codes for failed operations.
   * @param  rateBarrier   The barrier to use for controlling the rate of
   *                       modifies.  {@code null} if no rate-limiting
   *                       should be used.
   */
  ModRateThread(final int threadNumber, final LDAPConnection connection,
                final ValuePattern entryDN, final String[] attributes,
                final byte[] charSet, final int valueLength,
                final ValuePattern authzID, final long randomSeed,
                final CyclicBarrier startBarrier, final AtomicLong modCounter,
                final AtomicLong modDurations, final AtomicLong errorCounter,
                final ResultCodeCounter rcCounter,
                final FixedRateBarrier rateBarrier)
  {
    setName("ModRate Thread " + threadNumber);
    setDaemon(true);

    this.connection   = connection;
    this.entryDN      = entryDN;
    this.attributes   = attributes;
    this.charSet      = charSet;
    this.valueLength  = valueLength;
    this.authzID      = authzID;
    this.modCounter   = modCounter;
    this.modDurations = modDurations;
    this.errorCounter = errorCounter;
    this.rcCounter    = rcCounter;
    this.startBarrier = startBarrier;
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
    final ModifyRequest modifyRequest = new ModifyRequest("", mods);

    try
    {
      startBarrier.await();
    } catch (Exception e) {}

    while (! stopRequested.get())
    {
      modifyRequest.setDN(entryDN.nextValue());

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
      modifyRequest.setModifications(mods);

      if (authzID != null)
      {
        modifyRequest.setControls(new ProxiedAuthorizationV2RequestControl(
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
      catch (LDAPException le)
      {
        errorCounter.incrementAndGet();

        final ResultCode rc = le.getResultCode();
        rcCounter.increment(rc);
        resultCode.compareAndSet(null, rc);

        if (! le.getResultCode().isConnectionUsable())
        {
          try
          {
            connection.reconnect();
          } catch (final LDAPException le2) {}
        }
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
