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
package com.unboundid.ldap.sdk;



import java.util.concurrent.atomic.AtomicInteger;



/**
 * This class provides a simple listener that can be used to handle asynchronous
 * operation results.
 */
public class TestAsyncListener
       implements AsyncResultListener, AsyncCompareResultListener,
                  AsyncSearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9133547333781381420L;



  // The number of compare results received.
  private AtomicInteger compareResults;

  // The number of search result done messages received.
  private AtomicInteger searchResults;

  // The number of search result entry messages received.
  private AtomicInteger searchEntries;

  // The number of search result reference messages received.
  private AtomicInteger searchReferences;

  // The number of write operation results received.
  private AtomicInteger writeResults;

  // The message ID for the last result received on this listener.
  private int lastMessageID;

  // The last result received on this listener.
  private LDAPResult lastResult;



  /**
   * Creates a new instance of this test async listener.
   */
  public TestAsyncListener()
  {
    clear();
  }



  /**
   * Clears all results for this listener.
   */
  public void clear()
  {
    compareResults   = new AtomicInteger(0);
    searchResults    = new AtomicInteger(0);
    searchEntries    = new AtomicInteger(0);
    searchReferences = new AtomicInteger(0);
    writeResults     = new AtomicInteger(0);
    lastMessageID    = -1;
    lastResult       = null;
  }



  /**
   * Waits until a result is available, up to a maximum of 30 seconds.  Note
   * that for this method to work properly, it must be either invoked on a new
   * instance or a previous instance must have been cleared before sending the
   * new asynchronous request.
   *
   * @throws  LDAPException  If a timeout occurs.
   */
  public void waitForResult()
         throws LDAPException
  {
    long stopWaitingTime = System.currentTimeMillis() + 30000L;
    while (lastResult == null)
    {
      try
      {
        Thread.sleep(1);
      } catch (Exception e) {}

      if ((System.currentTimeMillis() >= stopWaitingTime) &&
          (lastResult == null))
      {
        throw new LDAPException(ResultCode.TIMEOUT, "Timeout in waitForResult");
      }
    }
  }



  /**
   * Retrieves the message ID for the last result received on this listener.
   *
   * @return  The message ID for the last result received on this listener, or
   *          -1 if there is none.
   */
  public int getLastMessageID()
  {
    return lastMessageID;
  }



  /**
   * Retrieves the last result received on this listener.
   *
   * @return  The last result received on this listener, or {@code null} if
   *          there is none.
   */
  public LDAPResult getLastResult()
  {
    return lastResult;
  }



  /**
   * Retrieves the number of write results received on this listener.
   *
   * @return  The number of write results received on this listener.
   */
  public int getWriteResults()
  {
    return writeResults.get();
  }



  /**
   * Retrieves the number of compare results received on this listener.
   *
   * @return  The number of compare results received on this listener.
   */
  public int getCompareResults()
  {
    return compareResults.get();
  }



  /**
   * Retrieves the number of search results received on this listener.
   *
   * @return  The number of search results received on this listener.
   */
  public int getSearchResults()
  {
    return searchResults.get();
  }



  /**
   * Retrieves the number of search entries received on this listener.
   *
   * @return  The number of search entries received on this listener.
   */
  public int getSearchEntries()
  {
    return searchEntries.get();
  }



  /**
   * Retrieves the number of search references received on this listener.
   *
   * @return  The number of search references received on this listener.
   */
  public int getSearchReferences()
  {
    return searchReferences.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ldapResultReceived(final AsyncRequestID requestID,
                                 final LDAPResult ldapResult)
  {
    writeResults.incrementAndGet();
    lastMessageID = requestID.getMessageID();
    lastResult    = ldapResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void compareResultReceived(final AsyncRequestID requestID,
                                    final CompareResult ldapResult)
  {
    compareResults.incrementAndGet();
    lastMessageID = requestID.getMessageID();
    lastResult    = ldapResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchResultReceived(final AsyncRequestID requestID,
                                   final SearchResult ldapResult)
  {
    searchResults.incrementAndGet();
    lastMessageID = requestID.getMessageID();
    lastResult    = ldapResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(SearchResultEntry searchEntry)
  {
    searchEntries.incrementAndGet();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(SearchResultReference searchReference)
  {
    searchReferences.incrementAndGet();
  }
}
