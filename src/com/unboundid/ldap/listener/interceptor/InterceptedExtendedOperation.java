/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
package com.unboundid.ldap.listener.interceptor;



import com.unboundid.ldap.listener.LDAPListenerClientConnection;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used in the course of
 * processing an extended operation via the {@link InMemoryOperationInterceptor}
 * API.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
final class InterceptedExtendedOperation
      extends InterceptedOperation
      implements InMemoryInterceptedExtendedRequest,
                 InMemoryInterceptedExtendedResult
{
  // The extended request for this operation.
  private ExtendedRequest extendedRequest;

  // The extended result for this operation.
  private ExtendedResult extendedResult;



  /**
   * Creates a new instance of this extended operation object with the provided
   * information.
   *
   * @param  clientConnection  The client connection with which this operation
   *                           is associated.
   * @param  messageID         The message ID for the associated operation.
   * @param  requestOp         The extended request protocol op in the request
   *                           received from the client.
   * @param  requestControls   The controls in the request received from the
   *                           client.
   */
  InterceptedExtendedOperation(
       final LDAPListenerClientConnection clientConnection, final int messageID,
       final ExtendedRequestProtocolOp requestOp,
       final Control... requestControls)
  {
    super(clientConnection, messageID);

    extendedRequest = requestOp.toExtendedRequest(requestControls);
    extendedResult  = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedRequest getRequest()
  {
    return extendedRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setRequest(final ExtendedRequest extendedRequest)
  {
    this.extendedRequest = extendedRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult getResult()
  {
    return extendedResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setResult(final ExtendedResult extendedResult)
  {
    this.extendedResult = extendedResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("InterceptedExtendedOperation(");
    appendCommonToString(buffer);
    buffer.append(", request=");
    buffer.append(extendedRequest);
    buffer.append(", result=");
    buffer.append(extendedResult);
    buffer.append(')');
  }
}
