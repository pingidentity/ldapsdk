/*
 * Copyright 2008-2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2011 UnboundID Corp.
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



import java.util.logging.Level;

import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.util.DebugType;
import com.unboundid.util.InternalUseOnly;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;



/**
 * This class provides a helper class used for processing asynchronous search
 * operations.
 */
@InternalUseOnly()
final class AsyncSearchHelper
      implements ResponseAcceptor, IntermediateResponseListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1006163445423767824L;



  // The async request ID created for the associated operation.
  private final AsyncRequestID asyncRequestID;

  // The async result listener to be notified when the response arrives.
  private final AsyncSearchResultListener resultListener;

  // The number of entries returned from this search.
  private int numEntries;

  // The number of references returned from this search.
  private int numReferences;

  // The intermediate response listener to be notified of any intermediate
  // response messages received.
  private final IntermediateResponseListener intermediateResponseListener;

  // The connection with which this async helper is associated.
  private final LDAPConnection connection;

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
  AsyncSearchHelper(final LDAPConnection connection, final int messageID,
       final AsyncSearchResultListener resultListener,
       final IntermediateResponseListener intermediateResponseListener)
  {
    this.connection                   = connection;
    this.resultListener               = resultListener;
    this.intermediateResponseListener = intermediateResponseListener;

    numEntries     = 0;
    numReferences  = 0;
    asyncRequestID = new AsyncRequestID(messageID, connection);
    createTime     = System.nanoTime();
  }



  /**
   * Retrieves the async request ID created for the associated operation.
   *
   * @return  The async request ID created for the associated operation.
   */
  AsyncRequestID getAsyncRequestID()
  {
    return asyncRequestID;
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  public void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    if (response instanceof ConnectionClosedResponse)
    {
      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String message = ccr.getMessage();
      if (message == null)
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_ASYNC_RESPONSE.get());
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_ASYNC_RESPONSE_WITH_MESSAGE.get(
                  message));
      }
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
  public void intermediateResponseReturned(
                   final IntermediateResponse intermediateResponse)
  {
    if (intermediateResponseListener == null)
    {
      debug(Level.WARNING, DebugType.LDAP,
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
