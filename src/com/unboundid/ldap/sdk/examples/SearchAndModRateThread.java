/*
 * Copyright 2010-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2019 Ping Identity Corporation
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



import java.util.List;
import java.util.Random;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.util.Debug;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.ResultCodeCounter;
import com.unboundid.util.ValuePattern;



/**
 * This class provides a thread that may be used to repeatedly perform search
 * and modify operations.
 */
final class SearchAndModRateThread
      extends Thread
{
  // Indicates whether a request has been made to stop running.
  private final AtomicBoolean stopRequested;

  // The counter used to track the number of errors encountered while searching.
  private final AtomicLong errorCounter;

  // The counter used to track the number of modifications performed.
  private final AtomicLong modCounter;

  // The value that will be updated with total duration of the modifies.
  private final AtomicLong modDurations;

  // The counter used to track the number of iterations remaining on the
  // current connection.
  private final AtomicLong remainingIterationsBeforeReconnect;

  // The counter used to track the number of searches performed.
  private final AtomicLong searchCounter;

  // The value that will be updated with total duration of the searches.
  private final AtomicLong searchDurations;

  // The thread that is actually performing the search and modify operations.
  private final AtomicReference<Thread> searchAndModThread;

  // The result code for this thread.
  private final AtomicReference<ResultCode> resultCode;

  // The set of characters that may be included in modify values.
  private final byte[] charSet;

  // The barrier that will be used to coordinate starting among all the threads.
  private final CyclicBarrier startBarrier;

  // The length to use for modify values.
  private final int valueLength;

  // The page size that should be used with the simple paged results request
  // control.
  private final Integer simplePageSize;

  // The connection to use for the searches.
  private LDAPConnection connection;

  // The set of controls that should be included in modify requests.
  private final List<Control> modifyControls;

  // The set of controls that should be included in search requests.
  private final List<Control> searchControls;

  // The number of iterations to request on a connection before closing and
  // re-establishing it.
  private final long iterationsBeforeReconnect;

  // The random number generator to use for this thread.
  private final Random random;

  // The result code counter to use for failed operations.
  private final ResultCodeCounter rcCounter;

  // A reference to the associated tool.
  private final SearchAndModRate searchAndModRate;

  // The search request to generate.
  private final SearchRequest searchRequest;

  // The set of attributes to modify.
  private final String[] modAttributes;

  // The value pattern to use for proxied authorization.
  private final ValuePattern authzID;

  // The value pattern to use for the base DNs.
  private final ValuePattern baseDN;

  // The value pattern to use for the filters.
  private final ValuePattern filter;

  // The barrier to use for controlling the rate of searches.  null if no
  // rate-limiting should be used.
  private final FixedRateBarrier fixedRateBarrier;



  /**
   * Creates a new search rate thread with the provided information.
   *
   * @param  searchAndModRate           A reference to the associated tool.
   * @param  threadNumber               The thread number for this thread.
   * @param  connection                 The connection to use for the searches.
   * @param  baseDN                     The value pattern to use for the base
   *                                    DNs.
   * @param  scope                      The scope to use for the searches.
   * @param  filter                     The value pattern for the filters.
   * @param  returnAttributes           The set of attributes to return for
   *                                    searches.
   * @param  modAttributes              The set of attributes to modify.
   * @param  valueLength                The length to use for generated modify
   *                                    values.
   * @param  charSet                    The set of characters that may be
   *                                    included in modify values.
   * @param  authzID                    The value pattern to use to generate
   *                                    authorization identities for use with
   *                                    the proxied authorization control.  It
   *                                    may be {@code null} if proxied
   *                                    authorization should not be used.
   * @param  simplePageSize             The page size that should be used with
   *                                    the simple paged results request
   *                                    control.  It may be {@code null} if the
   *                                    simple paged results control should not
   *                                    be used.
   * @param  searchControls             The set of controls to include in search
   *                                    requests.
   * @param  modifyControls             The set of controls to include in modify
   *                                    requests.
   * @param  iterationsBeforeReconnect  The number of iterations that should be
   *                                    processed on a connection before it is
   *                                    closed and replaced with a
   *                                    newly-established connection.
   * @param  randomSeed                 The seed to use for the random number
   *                                    generator.
   * @param  startBarrier               A barrier used to coordinate starting
   *                                    between all of the threads.
   * @param  searchCounter              A value that will be used to keep track
   *                                    of the total number of searches
   *                                    performed.
   * @param  modCounter                 A value that will be used to keep track
   *                                    of the total number of modifications
   *                                    performed.
   * @param  searchDurations            A value that will be used to keep track
   *                                    of the total duration for all searches.
   * @param  modDurations               A value that will be used to keep track
   *                                    of the total duration for all
   *                                    modifications.
   * @param  errorCounter               A value that will be used to keep track
   *                                    of the number of errors encountered
   *                                    while searching.
   * @param  rcCounter                  The result code counter to use for
   *                                    keeping track of the result codes for
   *                                    failed operations.
   * @param  rateBarrier                The barrier to use for controlling the
   *                                    rate of searches.  {@code null} if no
   *                                    rate-limiting should be used.
   */
  SearchAndModRateThread(final SearchAndModRate searchAndModRate,
       final int threadNumber, final LDAPConnection connection,
       final ValuePattern baseDN, final SearchScope scope,
       final ValuePattern filter, final String[] returnAttributes,
       final String[] modAttributes, final int valueLength,
       final byte[] charSet, final ValuePattern authzID,
       final Integer simplePageSize, final List<Control> searchControls,
       final List<Control> modifyControls, final long iterationsBeforeReconnect,
       final long randomSeed, final CyclicBarrier startBarrier,
       final AtomicLong searchCounter, final AtomicLong modCounter,
       final AtomicLong searchDurations, final AtomicLong modDurations,
       final AtomicLong errorCounter, final ResultCodeCounter rcCounter,
       final FixedRateBarrier rateBarrier)
  {
    setName("SearchAndModRate Thread " + threadNumber);
    setDaemon(true);

    this.searchAndModRate           = searchAndModRate;
    this.connection                 = connection;
    this.baseDN                     = baseDN;
    this.filter                     = filter;
    this.modAttributes              = modAttributes;
    this.valueLength                = valueLength;
    this.charSet                    = charSet;
    this.authzID                    = authzID;
    this.simplePageSize             = simplePageSize;
    this.searchControls             = searchControls;
    this.modifyControls             = modifyControls;
    this.iterationsBeforeReconnect = iterationsBeforeReconnect;
    this.searchCounter              = searchCounter;
    this.modCounter                 = modCounter;
    this.searchDurations            = searchDurations;
    this.modDurations               = modDurations;
    this.errorCounter               = errorCounter;
    this.rcCounter                  = rcCounter;
    this.startBarrier               = startBarrier;
    fixedRateBarrier                = rateBarrier;

    if (iterationsBeforeReconnect > 0L)
    {
      remainingIterationsBeforeReconnect =
           new AtomicLong(iterationsBeforeReconnect);
    }
    else
    {
      remainingIterationsBeforeReconnect = null;
    }

    connection.setConnectionName("search-and-mod-" + threadNumber);

    random             = new Random(randomSeed);
    resultCode         = new AtomicReference<>(null);
    searchAndModThread = new AtomicReference<>(null);
    stopRequested      = new AtomicBoolean(false);
    searchRequest      = new SearchRequest("", scope,
         Filter.createPresenceFilter("objectClass"), returnAttributes);
  }



  /**
   * Performs all processing for this thread.
   */
  @Override()
  public void run()
  {
    searchAndModThread.set(currentThread());

    final Modification[] mods = new Modification[modAttributes.length];
    final byte[] valueBytes = new byte[valueLength];
    final ASN1OctetString[] values = new ASN1OctetString[1];
    final ModifyRequest modifyRequest = new ModifyRequest("", mods);

    try
    {
      startBarrier.await();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

searchLoop:
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
          connection = searchAndModRate.getConnection();
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

      // If we're trying for a specific target rate, then we might need to
      // wait until issuing the next search.
      if (fixedRateBarrier != null)
      {
        fixedRateBarrier.await();
      }

      ProxiedAuthorizationV2RequestControl proxyControl = null;
      try
      {
        searchRequest.setBaseDN(baseDN.nextValue());
        searchRequest.setFilter(filter.nextValue());

        searchRequest.setControls(searchControls);

        if (authzID != null)
        {
          proxyControl = new ProxiedAuthorizationV2RequestControl(
               authzID.nextValue());
          searchRequest.addControl(proxyControl);
        }

        if (simplePageSize != null)
        {
          searchRequest.addControl(
               new SimplePagedResultsControl(simplePageSize));
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        errorCounter.incrementAndGet();

        final ResultCode rc = le.getResultCode();
        rcCounter.increment(rc);
        resultCode.compareAndSet(null, rc);
        continue;
      }

      final ASN1OctetString pagedResultCookie = null;
      final long searchStartTime = System.nanoTime();

      try
      {
        while (true)
        {
          final SearchResult r;
          try
          {
            r = connection.search(searchRequest);
          }
          catch (final LDAPSearchException lse)
          {
            Debug.debugException(lse);
            errorCounter.incrementAndGet();

            final ResultCode rc = lse.getResultCode();
            rcCounter.increment(rc);
            resultCode.compareAndSet(null, rc);

            if (! lse.getResultCode().isConnectionUsable())
            {
              connection.close();
              connection = null;
            }

            continue searchLoop;
          }

          for (int i=0; i < valueLength; i++)
          {
            valueBytes[i] = charSet[random.nextInt(charSet.length)];
          }

          values[0] = new ASN1OctetString(valueBytes);
          for (int i=0; i < modAttributes.length; i++)
          {
            mods[i] = new Modification(ModificationType.REPLACE,
                 modAttributes[i], values);
          }
          modifyRequest.setModifications(mods);

          modifyRequest.setControls(modifyControls);
          if (proxyControl != null)
          {
            modifyRequest.addControl(proxyControl);
          }

          for (final SearchResultEntry e : r.getSearchEntries())
          {
            if (fixedRateBarrier != null)
            {
              fixedRateBarrier.await();
            }

            modifyRequest.setDN(e.getDN());

            final long modStartTime = System.nanoTime();
            try
            {
              if (connection != null)
              {
                connection.modify(modifyRequest);
              }
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
            finally
            {
              modCounter.incrementAndGet();
              modDurations.addAndGet(System.nanoTime() - modStartTime);
            }
          }

          if (simplePageSize == null)
          {
            break;
          }

          try
          {
            final SimplePagedResultsControl sprResponse =
                 SimplePagedResultsControl.get(r);
            if ((sprResponse == null) || (! sprResponse.moreResultsToReturn()))
            {
              break;
            }

            searchRequest.setControls(searchControls);

            if (proxyControl != null)
            {
              searchRequest.addControl(proxyControl);
            }

            if (simplePageSize != null)
            {
              searchRequest.addControl(new SimplePagedResultsControl(
                   simplePageSize, sprResponse.getCookie()));
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            break;
          }
        }
      }
      finally
      {
        searchCounter.incrementAndGet();
        searchDurations.addAndGet(System.nanoTime() - searchStartTime);
      }
    }

    if (connection != null)
    {
      connection.close();
    }

    searchAndModThread.set(null);
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

    final Thread t = searchAndModThread.get();
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
