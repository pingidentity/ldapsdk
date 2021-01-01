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
package com.unboundid.ldap.sdk.examples;



import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.CRAMMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequest;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.Debug;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ResultCodeCounter;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ValuePattern;



/**
 * This class provides a thread that may be used to repeatedly perform
 * authentication processing.
 */
final class AuthRateThread
      extends Thread
{
  /**
   * The authentication type value that will be used to indicate that simple
   * authentication should be performed.
   */
  private static final int AUTH_TYPE_SIMPLE = 0;



  /**
   * The authentication type value that will be used to indicate that CRAM-MD5
   * authentication should be performed.
   */
  private static final int AUTH_TYPE_CRAM_MD5 = 1;



  /**
   * The authentication type value that will be used to indicate that DIGEST-MD5
   * authentication should be performed.
   */
  private static final int AUTH_TYPE_DIGEST_MD5 = 2;



  /**
   * The authentication type value that will be used to indicate that PLAIN
   * authentication should be performed.
   */
  private static final int AUTH_TYPE_PLAIN = 3;



  // Indicates whether a request has been made to stop running.
  @NotNull private final AtomicBoolean stopRequested;

  // The number of authrate threads that are currently running.
  @NotNull private final AtomicInteger runningThreads;

  // The counter used to track the number of searches performed.
  @NotNull private final AtomicLong authCounter;

  // The value that will be updated with total duration of the searches.
  @NotNull private final AtomicLong authDurations;

  // The counter used to track the number of errors encountered while searching.
  @NotNull private final AtomicLong errorCounter;

  // The result code for this thread.
  @NotNull private final AtomicReference<ResultCode> resultCode;

  // The thread that is actually performing the searches.
  @NotNull private final AtomicReference<Thread> authThread;

  // A reference to the associated authrate tool.
  @NotNull private final AuthRate authRate;

  // Indicates whether the authentication attempts should only include bind
  // operations without the initial search.
  private final boolean bindOnly;

  // The set of controls to include in bind requests.
  @NotNull private final Control[] bindControls;

  // The barrier that will be used to coordinate starting among all the threads.
  @NotNull private final CyclicBarrier startBarrier;

  // The barrier to use for controlling the rate of auths.  null if no
  // rate-limiting should be used.
  @Nullable private final FixedRateBarrier fixedRateBarrier;

  // The type of authentication to perform.
  private final int authType;

  // The connection to use for the binds.
  @Nullable private LDAPConnection bindConnection;

  // The connection to use for the searches.
  @Nullable private LDAPConnection searchConnection;

  // The result code counter to use for failed operations.
  @NotNull private final ResultCodeCounter rcCounter;

  // The search request to generate.
  @Nullable private final SearchRequest searchRequest;

  // The password to use to authenticate.
  @NotNull private final String userPassword;

  // The value pattern to use for the base DNs.
  @NotNull private final ValuePattern baseDN;

  //The value pattern to use for the filters.
  @Nullable private final ValuePattern filter;



  /**
   * Creates a new auth rate thread with the provided information.
   *
   * @param  authRate          A reference to the associated authrate tool.
   * @param  threadNumber      The thread number for this thread.
   * @param  searchConnection  The connection to use for the searches.
   * @param  bindConnection    The connection to use for the  binds.
   * @param  baseDN            The value pattern to use for the base DNs.
   * @param  scope             The scope to use for the searches.
   * @param  filter            The value pattern for the filters.
   * @param  attributes        The set of attributes to return.
   * @param  userPassword      The password to use for the bind operations.
   * @param  bindOnly          Indicates whether to only perform a bind without
   *                           first performing the initial search to find the
   *                           target user entry.
   * @param  authType          The type of authentication to perform.
   * @param  searchControls    The set of controls to include in search
   *                           requests.
   * @param  bindControls      The set of controls to include in bind requests.
   * @param  runningThreads    An atomic integer that will be incremented when
   *                           this thread starts, and decremented when it
   *                           completes.
   * @param  startBarrier      A barrier used to coordinate starting between all
   *                           of the threads.
   * @param  authCounter       A value that will be used to keep track of the
   *                           total number of authentications performed.
   * @param  authDurations     A value that will be used to keep track of the
   *                           total duration for all authentications.
   * @param  errorCounter      A value that will be used to keep track of the
   *                           number of errors encountered while searching.
   * @param  rcCounter         The result code counter to use for keeping track
   *                           of the result codes for failed operations.
   * @param  rateBarrier       The barrier to use for controlling the rate of
   *                           authorizations.  {@code null} if no rate-limiting
   *                           should be used.
   */
  AuthRateThread(@NotNull final AuthRate authRate, final int threadNumber,
                 @NotNull final LDAPConnection searchConnection,
                 @NotNull final LDAPConnection bindConnection,
                 @NotNull final ValuePattern baseDN,
                 @NotNull final SearchScope scope,
                 @Nullable final ValuePattern filter,
                 @NotNull final String[] attributes,
                 @NotNull final String userPassword,
                 final boolean bindOnly,
                 @NotNull final String authType,
                 @NotNull final List<Control> searchControls,
                 @NotNull final List<Control> bindControls,
                 @NotNull final AtomicInteger runningThreads,
                 @NotNull final CyclicBarrier startBarrier,
                 @NotNull final AtomicLong authCounter,
                 @NotNull final AtomicLong authDurations,
                 @NotNull final AtomicLong errorCounter,
                 @NotNull final ResultCodeCounter rcCounter,
                 @Nullable final FixedRateBarrier rateBarrier)
  {
    setName("AuthRate Thread " + threadNumber);
    setDaemon(true);

    this.authRate         = authRate;
    this.searchConnection = searchConnection;
    this.bindConnection   = bindConnection;
    this.baseDN           = baseDN;
    this.filter           = filter;
    this.userPassword     = userPassword;
    this.bindOnly         = bindOnly;
    this.authCounter      = authCounter;
    this.authDurations    = authDurations;
    this.errorCounter     = errorCounter;
    this.rcCounter        = rcCounter;
    this.runningThreads   = runningThreads;
    this.startBarrier     = startBarrier;
    fixedRateBarrier      = rateBarrier;

    searchConnection.setConnectionName("search-" + threadNumber);
    bindConnection.setConnectionName("bind-" + threadNumber);

    if (authType.equalsIgnoreCase("cram-md5"))
    {
      this.authType = AUTH_TYPE_CRAM_MD5;
    }
    else if (authType.equalsIgnoreCase("digest-md5"))
    {
      this.authType = AUTH_TYPE_DIGEST_MD5;
    }
    else if (authType.equalsIgnoreCase("plain"))
    {
      this.authType = AUTH_TYPE_PLAIN;
    }
    else
    {
      this.authType = AUTH_TYPE_SIMPLE;
    }

    resultCode    = new AtomicReference<>(null);
    authThread    = new AtomicReference<>(null);
    stopRequested = new AtomicBoolean(false);

    if (bindOnly)
    {
      searchRequest = null;
    }
    else
    {
      searchRequest = new SearchRequest("", scope,
           Filter.createPresenceFilter("objectClass"), attributes);
      searchRequest.setControls(searchControls);
    }

    if (bindControls.isEmpty())
    {
      this.bindControls = StaticUtils.NO_CONTROLS;
    }
    else
    {
      this.bindControls =
           bindControls.toArray(new Control[bindControls.size()]);
    }
  }



  /**
   * Performs all search processing for this thread.
   */
  @Override()
  public void run()
  {
    try
    {
      authThread.set(currentThread());
      runningThreads.incrementAndGet();

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
        if (searchConnection == null)
        {
          try
          {
            searchConnection = authRate.getConnection();
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

        if (bindConnection == null)
        {
          try
          {
            bindConnection = authRate.getConnection();
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

        if (! bindOnly)
        {
          try
          {
            searchRequest.setBaseDN(baseDN.nextValue());
            searchRequest.setFilter(filter.nextValue());
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
        }

        // If we're trying for a specific target rate, then we might need to
        // wait until starting the next authorization.
        if (fixedRateBarrier != null)
        {
          fixedRateBarrier.await();
        }

        final long startTime = System.nanoTime();

        try
        {
          final String bindDN;
          if (bindOnly)
          {
            bindDN = baseDN.nextValue();
          }
          else
          {
            final SearchResult r = searchConnection.search(searchRequest);
            switch (r.getEntryCount())
            {
              case 0:
                errorCounter.incrementAndGet();
                rcCounter.increment(ResultCode.NO_RESULTS_RETURNED);
                resultCode.compareAndSet(null, ResultCode.NO_RESULTS_RETURNED);
                continue;

              case 1:
                // This is acceptable, and we can continue processing.
                bindDN = r.getSearchEntries().get(0).getDN();
                break;

              default:
                errorCounter.incrementAndGet();
                rcCounter.increment(ResultCode.MORE_RESULTS_TO_RETURN);
                resultCode.compareAndSet(null,
                     ResultCode.MORE_RESULTS_TO_RETURN);
                continue;
            }
          }

          BindRequest bindRequest = null;
          switch (authType)
          {
            case AUTH_TYPE_SIMPLE:
              bindRequest =
                   new SimpleBindRequest(bindDN, userPassword, bindControls);
              break;

            case AUTH_TYPE_CRAM_MD5:
              bindRequest = new CRAMMD5BindRequest("dn:" + bindDN, userPassword,
                   bindControls);
              break;

            case AUTH_TYPE_DIGEST_MD5:
              bindRequest = new DIGESTMD5BindRequest("dn:" + bindDN, null,
                   userPassword, null, bindControls);
              break;

            case AUTH_TYPE_PLAIN:
              bindRequest = new PLAINBindRequest("dn:" + bindDN, userPassword,
                   bindControls);
              break;
          }

          bindConnection.bind(bindRequest);
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
            searchConnection.close();
            searchConnection = null;

            bindConnection.close();
            bindConnection = null;
          }
        }
        finally
        {
          authCounter.incrementAndGet();
          authDurations.addAndGet(System.nanoTime() - startTime);
        }
      }
    }
    finally
    {
      if (searchConnection != null)
      {
        searchConnection.close();
      }

      if (bindConnection != null)
      {
        bindConnection.close();
      }

      authThread.set(null);
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
    stopRequested.set(true);

    if (fixedRateBarrier != null)
    {
      fixedRateBarrier.shutdownRequested();
    }

    final Thread t = authThread.get();
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
