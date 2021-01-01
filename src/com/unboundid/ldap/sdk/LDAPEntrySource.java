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
package com.unboundid.ldap.sdk;



import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides an {@link EntrySource} that will read entries matching a
 * given set of search criteria from an LDAP directory server.  It may
 * optionally close the associated connection after all entries have been read.
 * <BR><BR>
 * This implementation processes the search asynchronously, which provides two
 * benefits:
 * <UL>
 *   <LI>It makes it easier to provide a throttling mechanism to prevent the
 *       entries from piling up and causing the client to run out of memory if
 *       the server returns them faster than the client can process them.  If
 *       this occurs, then the client will queue up a small number of entries
 *       but will then push back against the server to block it from sending
 *       additional entries until the client can catch up.  In this case, no
 *       entries should be lost, although some servers may impose limits on how
 *       long a search may be active or other forms of constraints.</LI>
 *   <LI>It makes it possible to abandon the search if the entry source is no
 *       longer needed (as signified by calling the {@link #close} method) and
 *       the caller intends to stop iterating through the results.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the process that may be used for iterating
 * across all entries containing the {@code person} object class using the LDAP
 * entry source API:
 * <PRE>
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("objectClass", "person"));
 * LDAPEntrySource entrySource = new LDAPEntrySource(connection,
 *      searchRequest, false);
 *
 * int entriesRead = 0;
 * int referencesRead = 0;
 * int exceptionsCaught = 0;
 * try
 * {
 *   while (true)
 *   {
 *     try
 *     {
 *       Entry entry = entrySource.nextEntry();
 *       if (entry == null)
 *       {
 *         // There are no more entries to be read.
 *         break;
 *       }
 *       else
 *       {
 *         // Do something with the entry here.
 *         entriesRead++;
 *       }
 *     }
 *     catch (SearchResultReferenceEntrySourceException e)
 *     {
 *       // The directory server returned a search result reference.
 *       SearchResultReference searchReference = e.getSearchReference();
 *       referencesRead++;
 *     }
 *     catch (EntrySourceException e)
 *     {
 *       // Some kind of problem was encountered (e.g., the connection is no
 *       // longer valid).  See if we can continue reading entries.
 *       exceptionsCaught++;
 *       if (! e.mayContinueReading())
 *       {
 *         break;
 *       }
 *     }
 *   }
 * }
 * finally
 * {
 *   entrySource.close();
 * }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPEntrySource
       extends EntrySource
       implements AsyncSearchResultListener
{
  /**
   * The bogus entry that will be used to signify the end of the results.
   */
  @NotNull private static final String END_OF_RESULTS = "END OF RESULTS";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1080386705549149135L;



  // The request ID associated with the asynchronous search.
  @NotNull private final AsyncRequestID asyncRequestID;

  // Indicates whether this entry source has been closed.
  @NotNull private final AtomicBoolean closed;

  // The search result for the search operation.
  @NotNull private final AtomicReference<SearchResult> searchResult;

  // Indicates whether to close the connection when this entry source is closed.
  private final boolean closeConnection;

  // The connection that will be used to read the entries.
  @NotNull private final LDAPConnection connection;

  // The queue from which entries will be read.
  @NotNull private final LinkedBlockingQueue<Object> queue;



  /**
   * Creates a new LDAP entry source with the provided information.
   *
   * @param  connection       The connection to the directory server from which
   *                          the entries will be read.  It must not be
   *                          {@code null}.
   * @param  searchRequest    The search request that will be used to identify
   *                          which entries should be returned.  It must not be
   *                          {@code null}, and it must not be configured with a
   *                          {@link SearchResultListener}.
   * @param  closeConnection  Indicates whether the provided connection should
   *                          be closed whenever all of the entries have been
   *                          read, or if the {@link #close} method is called.
   *
   * @throws  LDAPException  If there is a problem with the provided search
   *                         request or when trying to communicate with the
   *                         directory server over the provided connection.
   */
  public LDAPEntrySource(@NotNull final LDAPConnection connection,
                         @NotNull final SearchRequest searchRequest,
                         final boolean closeConnection)
         throws LDAPException
  {
    this(connection, searchRequest, closeConnection, 100);
  }



  /**
   * Creates a new LDAP entry source with the provided information.
   *
   * @param  connection       The connection to the directory server from which
   *                          the entries will be read.  It must not be
   *                          {@code null}.
   * @param  searchRequest    The search request that will be used to identify
   *                          which entries should be returned.  It must not be
   *                          {@code null}, and it must not be configured with a
   *                          {@link SearchResultListener}.
   * @param  closeConnection  Indicates whether the provided connection should
   *                          be closed whenever all of the entries have been
   *                          read, or if the {@link #close} method is called.
   * @param  queueSize        The size of the internal queue used to hold search
   *                          result entries until they can be consumed by the
   *                          {@link #nextEntry} method.  The value must be
   *                          greater than zero.
   *
   * @throws  LDAPException  If there is a problem with the provided search
   *                         request or when trying to communicate with the
   *                         directory server over the provided connection.
   */
  public LDAPEntrySource(@NotNull final LDAPConnection connection,
                         @NotNull final SearchRequest searchRequest,
                         final boolean closeConnection,
                         final int queueSize)
         throws LDAPException
  {
    Validator.ensureNotNull(connection, searchRequest);
    Validator.ensureTrue(queueSize > 0,
         "LDAPEntrySource.queueSize must be greater than 0.");

    this.connection      = connection;
    this.closeConnection = closeConnection;

    if (searchRequest.getSearchResultListener() != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
                              ERR_LDAP_ENTRY_SOURCE_REQUEST_HAS_LISTENER.get());
    }

    closed       = new AtomicBoolean(false);
    searchResult = new AtomicReference<>();
    queue        = new LinkedBlockingQueue<>(queueSize);

    final SearchRequest r = new SearchRequest(this, searchRequest.getControls(),
         searchRequest.getBaseDN(), searchRequest.getScope(),
         searchRequest.getDereferencePolicy(), searchRequest.getSizeLimit(),
         searchRequest.getTimeLimitSeconds(), searchRequest.typesOnly(),
         searchRequest.getFilter(), searchRequest.getAttributes());
    asyncRequestID = connection.asyncSearch(r);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry nextEntry()
         throws EntrySourceException
  {
    while (true)
    {
      if (closed.get() && queue.isEmpty())
      {
        return null;
      }

      final Object o;
      try
      {
        o = queue.poll(10L, TimeUnit.MILLISECONDS);
      }
      catch (final InterruptedException ie)
      {
        Debug.debugException(ie);
        Thread.currentThread().interrupt();
        throw new EntrySourceException(true,
             ERR_LDAP_ENTRY_SOURCE_NEXT_ENTRY_INTERRUPTED.get(), ie);
      }

      if (o != null)
      {
        if (o == END_OF_RESULTS)
        {
          return null;
        }
        else if (o instanceof Entry)
        {
          return (Entry) o;
        }
        else
        {
          throw (EntrySourceException) o;
        }
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void close()
  {
    closeInternal(true);
  }



  /**
   * Closes this LDAP entry source.
   *
   * @param  abandon  Indicates whether to attempt to abandon the search.
   */
  private void closeInternal(final boolean abandon)
  {
    addToQueue(END_OF_RESULTS);

    if (closed.compareAndSet(false, true))
    {
      if (abandon)
      {
        try
        {
          connection.abandon(asyncRequestID);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }

      if (closeConnection)
      {
        connection.close();
      }
    }
  }



  /**
   * Retrieves the search result for the search operation, if available.  It
   * will not be available until the search has completed (as indicated by a
   * {@code null} return value from the {@link #nextEntry} method).
   *
   * @return  The search result for the search operation, or {@code null} if it
   *          is not available (e.g., because the search has not yet completed).
   */
  @Nullable()
  public SearchResult getSearchResult()
  {
    return searchResult.get();
  }



  /**
   * {@inheritDoc}  This is intended for internal use only and should not be
   * called by anything outside of the LDAP SDK itself.
   */
  @InternalUseOnly()
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry searchEntry)
  {
    addToQueue(searchEntry);
  }



  /**
   * {@inheritDoc}  This is intended for internal use only and should not be
   * called by anything outside of the LDAP SDK itself.
   */
  @InternalUseOnly()
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference searchReference)
  {
    addToQueue(new SearchResultReferenceEntrySourceException(searchReference));
  }



  /**
   * {@inheritDoc}  This is intended for internal use only and should not be
   * called by anything outside of the LDAP SDK itself.
   */
  @InternalUseOnly()
  @Override()
  public void searchResultReceived(@NotNull final AsyncRequestID requestID,
                                   @NotNull final SearchResult searchResult)
  {
    this.searchResult.set(searchResult);

    if (! searchResult.getResultCode().equals(ResultCode.SUCCESS))
    {
      addToQueue(new EntrySourceException(false,
           new LDAPSearchException(searchResult)));
    }

    closeInternal(false);
  }



  /**
   * Adds the provided object to the queue, waiting as long as needed until it
   * has been added.
   *
   * @param  o  The object to be added.  It must not be {@code null}.
   */
  private void addToQueue(@NotNull final Object o)
  {
    while (true)
    {
      if (closed.get())
      {
        return;
      }

      try
      {
        if (queue.offer(o, 100L, TimeUnit.MILLISECONDS))
        {
          return;
        }
      }
      catch (final InterruptedException ie)
      {
        Debug.debugException(ie);
      }
    }
  }
}
