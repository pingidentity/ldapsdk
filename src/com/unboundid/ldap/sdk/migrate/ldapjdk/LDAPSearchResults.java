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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.util.Enumeration;
import java.util.NoSuchElementException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.AsyncRequestID;
import com.unboundid.ldap.sdk.AsyncSearchResultListener;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that provides access to data returned
 * in response to a search operation.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the {@link SearchResult} class
 * should be used instead.
 */
@Mutable()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPSearchResults
       implements Enumeration<Object>, AsyncSearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7884355145560496230L;



  // The asynchronous request ID for these search results.
  @Nullable private volatile AsyncRequestID asyncRequestID;

  // Indicates whether the search has been abandoned.
  @NotNull private final AtomicBoolean searchAbandoned;

  // Indicates whether the end of the result set has been reached.
  @NotNull private final AtomicBoolean searchDone;

  // The number of items that can be read immediately without blocking.
  @NotNull private final AtomicInteger count;

  // The set of controls for the last result element returned.
  @NotNull private final AtomicReference<Control[]> lastControls;

  // The next object to be returned.
  @NotNull private final AtomicReference<Object> nextResult;

  // The search result done message for the search.
  @NotNull private final AtomicReference<SearchResult> searchResult;

  // The maximum length of time in milliseconds to wait for a response.
  private final long maxWaitTime;

  // The queue used to hold results.
  @NotNull private final LinkedBlockingQueue<Object> resultQueue;



  /**
   * Creates a new LDAP search results object.
   */
  public LDAPSearchResults()
  {
    this(0L);
  }



  /**
   * Creates a new LDAP search results object with the specified maximum wait
   * time.
   *
   * @param  maxWaitTime  The maximum wait time in milliseconds.
   */
  public LDAPSearchResults(final long maxWaitTime)
  {
    this.maxWaitTime = maxWaitTime;

    asyncRequestID = null;
    searchAbandoned = new AtomicBoolean(false);
    searchDone      = new AtomicBoolean(false);
    count           = new AtomicInteger(0);
    lastControls    = new AtomicReference<>();
    nextResult      = new AtomicReference<>();
    searchResult    = new AtomicReference<>();
    resultQueue     = new LinkedBlockingQueue<>(50);
  }



  /**
   * Indicates that this search request has been abandoned.
   */
  void setAbandoned()
  {
    searchAbandoned.set(true);
  }



  /**
   * Retrieves the asynchronous request ID for the associates search operation.
   *
   * @return  The asynchronous request ID for the associates search operation.
   */
  @Nullable()
  AsyncRequestID getAsyncRequestID()
  {
    return asyncRequestID;
  }



  /**
   * Sets the asynchronous request ID for the associated search operation.
   *
   * @param  asyncRequestID  The asynchronous request ID for the associated
   *                         search operation.
   */
  void setAsyncRequestID(@Nullable final AsyncRequestID asyncRequestID)
  {
    this.asyncRequestID = asyncRequestID;
  }



  /**
   * Retrieves the next object returned from the server, if possible.  When this
   * method returns, then the {@code nextResult} reference will also contain the
   * object that was returned.
   *
   * @return  The next object returned from the server, or {@code null} if there
   *          are no more objects to return.
   */
  @Nullable()
  private Object nextObject()
  {
    Object o = nextResult.get();
    if (o != null)
    {
      return o;
    }

    o = resultQueue.poll();
    if (o != null)
    {
      nextResult.set(o);
      return o;
    }

    if (searchDone.get() || searchAbandoned.get())
    {
      return null;
    }

    try
    {
      final long stopWaitTime;
      if (maxWaitTime > 0L)
      {
        stopWaitTime = System.currentTimeMillis() + maxWaitTime;
      }
      else
      {
        stopWaitTime = Long.MAX_VALUE;
      }

      while ((! searchAbandoned.get()) &&
             (System.currentTimeMillis() < stopWaitTime))
      {
        o = resultQueue.poll(100L, TimeUnit.MILLISECONDS);
        if (o != null)
        {
          break;
        }
      }

      if (o == null)
      {
        if (searchAbandoned.get())
        {
          o = new SearchResult(-1, ResultCode.USER_CANCELED, null, null, null,
               0, 0, null);
          count.incrementAndGet();
        }
        else
        {
          o = new SearchResult(-1, ResultCode.TIMEOUT, null, null, null, 0, 0,
               null);
          count.incrementAndGet();
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }

      o = new SearchResult(-1, ResultCode.USER_CANCELED, null, null, null, 0, 0,
           null);
      count.incrementAndGet();
    }

    nextResult.set(o);
    return o;
  }



  /**
   * Indicates whether there are any more search results to return.
   *
   * @return  {@code true} if there are more search results to return, or
   *          {@code false} if not.
   */
  @Override()
  public boolean hasMoreElements()
  {
    final Object o = nextObject();
    if (o == null)
    {
      return false;
    }

    if (o instanceof SearchResult)
    {
      final SearchResult r = (SearchResult) o;
      if (r.getResultCode().equals(ResultCode.SUCCESS))
      {
        lastControls.set(r.getResponseControls());
        searchDone.set(true);
        nextResult.set(null);
        return false;
      }
    }

    return true;
  }



  /**
   * Retrieves the next element in the set of search results.
   *
   * @return  The next element in the set of search results.
   *
   * @throws  NoSuchElementException  If there are no more results.
   */
  @Override()
  @NotNull()
  public Object nextElement()
         throws NoSuchElementException
  {
    final Object o = nextObject();
    if (o == null)
    {
      throw new NoSuchElementException();
    }

    nextResult.set(null);
    count.decrementAndGet();

    if (o instanceof SearchResultEntry)
    {
      final SearchResultEntry e = (SearchResultEntry) o;
      lastControls.set(e.getControls());
      return new LDAPEntry(e);
    }
    else if (o instanceof SearchResultReference)
    {
      final SearchResultReference r = (SearchResultReference) o;
      lastControls.set(r.getControls());
      return new LDAPReferralException(r);
    }
    else
    {
      final SearchResult r = (SearchResult) o;
      searchDone.set(true);
      nextResult.set(null);
      lastControls.set(r.getResponseControls());
      return new LDAPException(r.getDiagnosticMessage(),
           r.getResultCode().intValue(), r.getDiagnosticMessage(),
           r.getMatchedDN());
    }
  }



  /**
   * Retrieves the next entry from the set of search results.
   *
   * @return  The next entry from the set of search results.
   *
   * @throws  LDAPException  If there are no more elements to return, or if
   *                         the next element in the set of results is not an
   *                         entry.
   */
  @NotNull()
  public LDAPEntry next()
         throws LDAPException
  {
    if (! hasMoreElements())
    {
      throw new LDAPException(null, ResultCode.NO_RESULTS_RETURNED_INT_VALUE);
    }

    final Object o = nextElement();
    if (o instanceof LDAPEntry)
    {
      return (LDAPEntry) o;
    }

    throw (LDAPException) o;
  }



  /**
   * Retrieves the number of results that are available for immediate
   * processing.
   *
   * @return  The number of results that are available for immediate processing.
   */
  public int getCount()
  {
    return count.get();
  }



  /**
   * Retrieves the response controls for the last result element returned, or
   * for the search itself if the search has completed.
   *
   * @return  The response controls for the last result element returned, or
   *          {@code null} if no elements have yet been returned or if the last
   *          element did not include any controls.
   */
  @Nullable()
  public LDAPControl[] getResponseControls()
  {
    final Control[] controls = lastControls.get();
    if ((controls == null) || (controls.length == 0))
    {
      return null;
    }

    return LDAPControl.toLDAPControls(controls);
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry searchEntry)
  {
    if (searchDone.get())
    {
      return;
    }

    try
    {
      resultQueue.put(searchEntry);
      count.incrementAndGet();
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }

      searchDone.set(true);
    }
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference searchReference)
  {
    if (searchDone.get())
    {
      return;
    }

    try
    {
      resultQueue.put(searchReference);
      count.incrementAndGet();
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }

      searchDone.set(true);
    }
  }



  /**
   * Indicates that the provided search result has been received in response to
   * an asynchronous search operation.  Note that automatic referral following
   * is not supported for asynchronous operations, so it is possible that this
   * result could include a referral.
   *
   * @param  requestID     The async request ID of the request for which the
   *                       response was received.
   * @param  searchResult  The search result that has been received.
   */
  @InternalUseOnly()
  @Override()
  public void searchResultReceived(@NotNull final AsyncRequestID requestID,
                                   @NotNull final SearchResult searchResult)
  {
    if (searchDone.get())
    {
      return;
    }

    try
    {
      resultQueue.put(searchResult);
      if (! searchResult.getResultCode().equals(ResultCode.SUCCESS))
      {
        count.incrementAndGet();
      }
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }

      searchDone.set(true);
    }
  }
}
