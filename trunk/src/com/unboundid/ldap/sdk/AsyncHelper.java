/*
 * Copyright 2008-2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2010 UnboundID Corp.
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

import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.util.DebugType;
import com.unboundid.util.InternalUseOnly;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;



/**
 * This class provides a helper class used for processing asynchronous add,
 * delete, modify, and modify DN operations.
 */
@InternalUseOnly()
final class AsyncHelper
      implements ResponseAcceptor, IntermediateResponseListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7186731025240177443L;



  // The async result listener to be notified when the response arrives.
  private final AsyncResultListener resultListener;

  // The BER type for the operation with which this helper is associated.
  private final byte opType;

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
   * @param  opType                        The BER type for the expected
   *                                       response protocol op for this helper.
   * @param  resultListener                The async result listener to be
   *                                       notified when the response arrives.
   * @param  intermediateResponseListener  The intermediate response listener to
   *                                       be notified of any intermediate
   *                                       response messages received.
   */
  @InternalUseOnly()
  AsyncHelper(final LDAPConnection connection, final byte opType,
              final AsyncResultListener resultListener,
              final IntermediateResponseListener intermediateResponseListener)
  {
    this.resultListener               = resultListener;
    this.opType                       = opType;
    this.intermediateResponseListener = intermediateResponseListener;
    this.connection                   = connection;

    createTime = System.nanoTime();
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  public void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    final long responseTime = System.nanoTime() - createTime;
    if (response instanceof ConnectionClosedResponse)
    {
      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String message = ccr.getMessage();
      if (message == null)
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_CONN_CLOSED_WAITING_FOR_ASYNC_RESPONSE.get());
      }
      else
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_CONN_CLOSED_WAITING_FOR_ASYNC_RESPONSE_WITH_MESSAGE.get(
                  message));
      }

    }

    switch (opType)
    {
      case LDAPMessage.PROTOCOL_OP_TYPE_ADD_RESPONSE:
        connection.getConnectionStatistics().incrementNumAddResponses(
             responseTime);
        break;
      case LDAPMessage.PROTOCOL_OP_TYPE_DELETE_RESPONSE:
        connection.getConnectionStatistics().incrementNumDeleteResponses(
             responseTime);
        break;
      case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
        connection.getConnectionStatistics().incrementNumModifyResponses(
             responseTime);
        break;
      case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
        connection.getConnectionStatistics().incrementNumModifyDNResponses(
             responseTime);
        break;
    }

    final LDAPResult result = (LDAPResult) response;
    resultListener.ldapResultReceived(
         new AsyncRequestID(result.getMessageID()), result);
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
