/*
 * Copyright 2009-2013 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2013 UnboundID Corp.
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
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;



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



  // Indicates whether the end of the result set has been reached.
  private final AtomicBoolean searchDone;

  // The number of items that can be read immediately without blocking.
  private final AtomicInteger count;

  // The set of controls for the last result element returned.
  private final AtomicReference<Control[]> lastControls;

  // The next object to be returned.
  private final AtomicReference<Object> nextResult;

  // The search result done message for the search.
  private final AtomicReference<SearchResult> searchResult;

  // The maximum length of time in milliseconds to wait for a response.
  private final long maxWaitTime;

  // The queue used to hold results.
  private final LinkedBlockingQueue<Object> resultQueue;



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

    searchDone   = new AtomicBoolean(false);
    count        = new AtomicInteger(0);
    lastControls = new AtomicReference<Control[]>();
    nextResult   = new AtomicReference<Object>();
    searchResult = new AtomicReference<SearchResult>();
    resultQueue  = new LinkedBlockingQueue<Object>(50);
  }



  /**
   * Retrieves the next object returned from the server, if possible.  When this
   * method returns, then the {@code nextResult} reference will also contain the
   * object that was returned.
   *
   * @return  The next object returned from the server, or {@code null} if there
   *          are no more objects to return.
   */
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

    if (searchDone.get())
    {
      return null;
    }

    try
    {
      if (maxWaitTime > 0)
      {
        o = resultQueue.poll(maxWaitTime, TimeUnit.MILLISECONDS);
        if (o == null)
        {
          o = new SearchResult(-1, ResultCode.TIMEOUT, null, null, null, 0, 0,
               null);
          count.incrementAndGet();
        }
      }
      else
      {
        o = resultQueue.take();
      }
    }
    catch (Exception e)
    {
      debugException(e);

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
  public void searchEntryReturned(final SearchResultEntry searchEntry)
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
    catch (Exception e)
    {
      // This should never happen.
      debugException(e);
      searchDone.set(true);
    }
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
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
    catch (Exception e)
    {
      // This should never happen.
      debugException(e);
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
  public void searchResultReceived(final AsyncRequestID requestID,
                                   final SearchResult searchResult)
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
    catch (Exception e)
    {
      // This should never happen.
      debugException(e);
      searchDone.set(true);
    }
  }
}
