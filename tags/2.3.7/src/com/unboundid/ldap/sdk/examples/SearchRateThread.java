/*
 * Copyright 2008-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2014 UnboundID Corp.
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
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.util.Debug;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.ResultCodeCounter;
import com.unboundid.util.ValuePattern;



/**
 * This class provides a thread that may be used to repeatedly perform searches.
 */
final class SearchRateThread
      extends Thread
      implements SearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6714705986829223364L;



  // Indicates whether a request has been made to stop running.
  private final AtomicBoolean stopRequested;

  // The counter used to track the number of entries returned.
  private final AtomicLong entryCounter;

  // The counter used to track the number of errors encountered while searching.
  private final AtomicLong errorCounter;

  // The counter used to track the number of iterations remaining on the
  // current connection.
  private final AtomicLong remainingIterationsBeforeReconnect;

  // The counter used to track the number of searches performed.
  private final AtomicLong searchCounter;

  // The value that will be updated with total duration of the searches.
  private final AtomicLong searchDurations;

  // The thread that is actually performing the searches.
  private final AtomicReference<Thread> searchThread;

  // Indicates whether to operate in asynchronous mode.
  private final boolean async;

  // The connection to use for the searches.
  private LDAPConnection connection;

  // The result code for this thread.
  private final AtomicReference<ResultCode> resultCode;

  // The barrier that will be used to coordinate starting among all the threads.
  private final CyclicBarrier startBarrier;

  // The number of iterations to request on a connection before closing and
  // re-establishing it.
  private final long iterationsBeforeReconnect;

  // The result code counter to use for failed operations.
  private final ResultCodeCounter rcCounter;

  // A reference to the searchrate tool.
  private final SearchRate searchRate;

  // The search request to generate.
  private final SearchRequest searchRequest;

  // The scope to use for search requests.
  private final SearchScope scope;

  // The semaphore used to limit total number of outstanding asynchronous
  // requests.
  private final Semaphore asyncSemaphore;

  // The set of requested attributes for search requests.
  private final String[] attributes;

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
   * @param  searchRate                 A reference to the associated searchrate
   *                                    tool.
   * @param  threadNumber               The thread number for this thread.
   * @param  connection                 The connection to use for the searches.
   * @param  async                      Indicates whether to operate in
   *                                    asynchronous mode.
   * @param  baseDN                     The value pattern to use for the base
   *                                    DNs.
   * @param  scope                      The scope to use for the searches.
   * @param  filter                     The value pattern for the filters.
   * @param  attributes                 The set of attributes to return.
   * @param  authzID                    The value pattern to use to generate
   *                                    authorization identities for use with
   *                                    the proxied authorization control.  It
   *                                    may be {@code null} if proxied
   *                                    authorization should not be used.
   * @param  iterationsBeforeReconnect  The number of iterations that should be
   *                                    processed on a connection before it is
   *                                    closed and replaced with a
   *                                    newly-established connection.
   * @param  startBarrier               A barrier used to coordinate starting
   *                                    between all of the threads.
   * @param  searchCounter              A value that will be used to keep track
   *                                    of the total number of searches
   *                                    performed.
   * @param  entryCounter               A value that will be used to keep track
   *                                    of the total number of entries returned.
   * @param  searchDurations            A value that will be used to keep track
   *                                    of the total duration for all searches.
   * @param  errorCounter               A value that will be used to keep track
   *                                    of the number of errors encountered
   *                                    while searching.
   * @param  rcCounter                  The result code counter to use for
   *                                    keeping track of the result codes for
   *                                    failed operations.
   * @param  rateBarrier                The barrier to use for controlling the
   *                                    rate of searches.  {@code null} if no
   *                                    rate-limiting should be used.
   * @param  asyncSemaphore             The semaphore used ot limit the total
   *                                    number of outstanding asynchronous
   *                                    requests.
   */
  SearchRateThread(final SearchRate searchRate, final int threadNumber,
                   final LDAPConnection connection, final boolean async,
                   final ValuePattern baseDN, final SearchScope scope,
                   final ValuePattern filter, final String[] attributes,
                   final ValuePattern authzID,
                   final long iterationsBeforeReconnect,
                   final CyclicBarrier startBarrier,
                   final AtomicLong searchCounter,
                   final AtomicLong entryCounter,
                   final AtomicLong searchDurations,
                   final AtomicLong errorCounter,
                   final ResultCodeCounter rcCounter,
                   final FixedRateBarrier rateBarrier,
                   final Semaphore asyncSemaphore)
  {
    setName("SearchRate Thread " + threadNumber);
    setDaemon(true);

    this.searchRate                = searchRate;
    this.connection                = connection;
    this.async                     = async;
    this.baseDN                    = baseDN;
    this.scope                     = scope;
    this.filter                    = filter;
    this.attributes                = attributes;
    this.authzID                   = authzID;
    this.iterationsBeforeReconnect = iterationsBeforeReconnect;
    this.searchCounter             = searchCounter;
    this.entryCounter              = entryCounter;
    this.searchDurations           = searchDurations;
    this.errorCounter              = errorCounter;
    this.rcCounter                 = rcCounter;
    this.startBarrier              = startBarrier;
    this.asyncSemaphore            = asyncSemaphore;
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

    connection.setConnectionName("search-" + threadNumber);

    resultCode    = new AtomicReference<ResultCode>(null);
    searchThread  = new AtomicReference<Thread>(null);
    stopRequested = new AtomicBoolean(false);
    searchRequest = new SearchRequest(this, "", scope,
         Filter.createPresenceFilter("objectClass"), attributes);
  }



  /**
   * Performs all search processing for this thread.
   */
  @Override()
  public void run()
  {
    searchThread.set(currentThread());

    try
    {
      startBarrier.await();
    }
    catch (Exception e)
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
          connection = searchRate.getConnection();
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

      if (async)
      {
        if (asyncSemaphore != null)
        {
          try
          {
            asyncSemaphore.acquire();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            errorCounter.incrementAndGet();

            final ResultCode rc = ResultCode.LOCAL_ERROR;
            rcCounter.increment(rc);
            resultCode.compareAndSet(null, rc);
            continue;
          }
        }

        final SearchRateAsyncListener listener = new SearchRateAsyncListener(
             searchCounter, entryCounter, searchDurations, errorCounter,
             rcCounter, asyncSemaphore, resultCode);

        try
        {
          connection.asyncSearch(new SearchRequest(listener, baseDN.nextValue(),
               scope, filter.nextValue(), attributes));
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          errorCounter.incrementAndGet();

          final ResultCode rc = le.getResultCode();
          rcCounter.increment(rc);
          resultCode.compareAndSet(null, rc);

          if (asyncSemaphore != null)
          {
            asyncSemaphore.release();
          }

          continue;
        }
      }
      else
      {
        try
        {
          searchRequest.setBaseDN(baseDN.nextValue());
          searchRequest.setFilter(filter.nextValue());

          if (authzID != null)
          {
            searchRequest.setControls(new ProxiedAuthorizationV2RequestControl(
                 authzID.nextValue()));
          }
        }
        catch (LDAPException le)
        {
          Debug.debugException(le);
          errorCounter.incrementAndGet();

          final ResultCode rc = le.getResultCode();
          rcCounter.increment(rc);
          resultCode.compareAndSet(null, rc);
          continue;
        }

        final long startTime = System.nanoTime();

        try
        {
          final SearchResult r = connection.search(searchRequest);
          entryCounter.addAndGet(r.getEntryCount());
        }
        catch (LDAPSearchException lse)
        {
          Debug.debugException(lse);
          errorCounter.incrementAndGet();
          entryCounter.addAndGet(lse.getEntryCount());

          final ResultCode rc = lse.getResultCode();
          rcCounter.increment(rc);
          resultCode.compareAndSet(null, rc);

          if (! lse.getResultCode().isConnectionUsable())
          {
            connection.close();
            connection = null;
          }
        }

        searchCounter.incrementAndGet();
        searchDurations.addAndGet(System.nanoTime() - startTime);
      }
    }

    // Wait for all outstanding asynchronous searches to complete before closing
    // the connection.
    if (asyncSemaphore != null)
    {
      while (asyncSemaphore.availablePermits() <
           searchRate.getMaxOutstandingRequests())
      {
        try
        {
          Thread.sleep(1L);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    if (connection != null)
    {
      connection.close();
    }

    searchThread.set(null);
  }



  /**
   * Indicates that this thread should stop running.  It will not wait for the
   * thread to complete before returning.
   */
  void signalShutdown()
  {
    stopRequested.set(true);

    if (fixedRateBarrier != null)
    {
      fixedRateBarrier.shutdownRequested();
    }
  }



  /**
   * Waits for this thread to stop running.
   *
   * @return  A result code that provides information about whether any errors
   *          were encountered during processing.
   */
  ResultCode waitForShutdown()
  {
    final Thread t = searchThread.get();
    if (t != null)
    {
      try
      {
        t.join();
      }
      catch (Exception e)
      {
        Debug.debugException(e);
      }
    }

    resultCode.compareAndSet(null, ResultCode.SUCCESS);
    return resultCode.get();
  }



  /**
   * {@inheritDoc}
   */
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    // No implementation required.
  }



  /**
   * {@inheritDoc}
   */
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    // No implementation required.
  }
}
