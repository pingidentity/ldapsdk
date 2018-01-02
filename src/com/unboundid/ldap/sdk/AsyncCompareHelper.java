/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import com.unboundid.util.DebugType;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;



/**
 * This class provides a helper class used for processing asynchronous compare
 * operations.
 */
@InternalUseOnly()
final class AsyncCompareHelper
      implements CommonAsyncHelper, IntermediateResponseListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8888333889563000881L;



  // The async result listener to be notified when the response arrives.
  private final AsyncCompareResultListener resultListener;

  // The async request ID created for the associated operation.
  private final AsyncRequestID asyncRequestID;

  // Indicates whether the final response has been returned.
  private final AtomicBoolean responseReturned;

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
  AsyncCompareHelper(final LDAPConnection connection, final int messageID,
       final AsyncCompareResultListener resultListener,
       final IntermediateResponseListener intermediateResponseListener)
  {
    this.connection                   = connection;
    this.resultListener               = resultListener;
    this.intermediateResponseListener = intermediateResponseListener;

    asyncRequestID   = new AsyncRequestID(messageID, connection);
    responseReturned = new AtomicBoolean(false);
    createTime       = System.nanoTime();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AsyncRequestID getAsyncRequestID()
  {
    return asyncRequestID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
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
  public OperationType getOperationType()
  {
    return OperationType.COMPARE;
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    if (! responseReturned.compareAndSet(false, true))
    {
      return;
    }

    final long responseTime = System.nanoTime() - createTime;

    final CompareResult result;
    if (response instanceof ConnectionClosedResponse)
    {
      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String msg = ccr.getMessage();
      if (msg == null)
      {
        result = new CompareResult(asyncRequestID.getMessageID(),
             ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_ASYNC_RESPONSE.get(), null,
             StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS);
      }
      else
      {
        result = new CompareResult(asyncRequestID.getMessageID(),
             ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_ASYNC_RESPONSE_WITH_MESSAGE.get(msg),
             null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS);
      }
    }
    else
    {
      result = (CompareResult) response;
    }

    connection.getConnectionStatistics().incrementNumCompareResponses(
         responseTime);
    resultListener.compareResultReceived(asyncRequestID, result);
    asyncRequestID.setResult(result);
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
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
