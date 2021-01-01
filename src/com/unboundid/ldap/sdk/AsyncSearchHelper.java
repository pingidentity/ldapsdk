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



import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;

import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a helper class used for processing asynchronous search
 * operations.
 */
@InternalUseOnly()
final class AsyncSearchHelper
      implements CommonAsyncHelper, IntermediateResponseListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1006163445423767824L;



  // The async request ID created for the associated operation.
  @NotNull private final AsyncRequestID asyncRequestID;

  // The async result listener to be notified when the response arrives.
  @NotNull private final AsyncSearchResultListener resultListener;

  // Indicates whether the final response has been returned.
  @NotNull private final AtomicBoolean responseReturned;

  // The number of entries returned from this search.
  private int numEntries;

  // The number of references returned from this search.
  private int numReferences;

  // The intermediate response listener to be notified of any intermediate
  // response messages received.
  @Nullable private final IntermediateResponseListener
       intermediateResponseListener;

  // The connection with which this async helper is associated.
  @NotNull private final LDAPConnection connection;

  // The time that this async helper was created.
  private final long createTime;



  /**
   * Creates a new instance of this async helper that will be used to forward
   * decoded results to the provided async result listener.
   *
   * @param  connection                    The connection with which this async
   *                                       helper is associated.
   * @param  messageID                     The message ID for the associated
   *                                       operation.
   * @param  resultListener                The async result listener to be
   *                                       notified when the response arrives.
   * @param  intermediateResponseListener  The intermediate response listener to
   *                                       be notified of any intermediate
   *                                       response messages received.
   */
  @InternalUseOnly()
  AsyncSearchHelper(@NotNull final LDAPConnection connection,
       final int messageID,
       @NotNull final AsyncSearchResultListener resultListener,
       @Nullable final IntermediateResponseListener
                         intermediateResponseListener)
  {
    this.connection                   = connection;
    this.resultListener               = resultListener;
    this.intermediateResponseListener = intermediateResponseListener;

    numEntries       = 0;
    numReferences    = 0;
    asyncRequestID   = new AsyncRequestID(messageID, connection);
    responseReturned = new AtomicBoolean(false);
    createTime       = System.nanoTime();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AsyncRequestID getAsyncRequestID()
  {
    return asyncRequestID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnection getConnection()
  {
    return connection;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public long getCreateTimeNanos()
  {
    return createTime;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public OperationType getOperationType()
  {
    return OperationType.SEARCH;
  }



  /**
   * Retrieves the number of entries returned for the search.
   *
   * @return  The number of entries returned for the search.
   */
  int getNumEntries()
  {
    return numEntries;
  }



  /**
   * Retrieves the number of references returned for the search.
   *
   * @return  The number of references returned for the search.
   */
  int getNumReferences()
  {
    return numReferences;
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void responseReceived(@Nullable final LDAPResponse response)
         throws LDAPException
  {
    if (responseReturned.get())
    {
      return;
    }

    if (response instanceof ConnectionClosedResponse)
    {
      if (! responseReturned.compareAndSet(false, true))
      {
        return;
      }

      final String message;
      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String ccrMessage = ccr.getMessage();
      if (ccrMessage == null)
      {
        message = ERR_CONN_CLOSED_WAITING_FOR_ASYNC_RESPONSE.get();
      }
      else
      {
        message = ERR_CONN_CLOSED_WAITING_FOR_ASYNC_RESPONSE_WITH_MESSAGE.get(
             ccrMessage);
      }

      connection.getConnectionStatistics().incrementNumSearchResponses(
           numEntries, numReferences, System.nanoTime() - createTime);

      final SearchResult searchResult = new SearchResult(
           asyncRequestID.getMessageID(), ccr.getResultCode(), message, null,
           StaticUtils.NO_STRINGS, numEntries, numReferences,
           StaticUtils.NO_CONTROLS);
      resultListener.searchResultReceived(asyncRequestID, searchResult);
      asyncRequestID.setResult(searchResult);
    }
    else if (response instanceof SearchResultEntry)
    {
      numEntries++;
      resultListener.searchEntryReturned((SearchResultEntry) response);
    }
    else if (response instanceof SearchResultReference)
    {
      numReferences++;
      resultListener.searchReferenceReturned((SearchResultReference) response);
    }
    else
    {
      if (! responseReturned.compareAndSet(false, true))
      {
        return;
      }

      connection.getConnectionStatistics().incrementNumSearchResponses(
           numEntries, numReferences, System.nanoTime() - createTime);

      final SearchResult searchResult = (SearchResult) response;
      searchResult.setCounts(numEntries, null, numReferences, null);
      resultListener.searchResultReceived(asyncRequestID, searchResult);
      asyncRequestID.setResult(searchResult);
    }
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void intermediateResponseReturned(
                   @NotNull final IntermediateResponse intermediateResponse)
  {
    if (intermediateResponseListener == null)
    {
      Debug.debug(Level.WARNING, DebugType.LDAP,
            WARN_INTERMEDIATE_RESPONSE_WITH_NO_LISTENER.get(
                 String.valueOf(intermediateResponse)));
    }
    else
    {
      intermediateResponseListener.intermediateResponseReturned(
           intermediateResponse);
    }
  }
}
