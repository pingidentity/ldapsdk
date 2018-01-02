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
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used in the course of
 * processing a simple bind operation via the
 * {@link InMemoryOperationInterceptor} API.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
final class InterceptedSimpleBindOperation
      extends InterceptedOperation
      implements InMemoryInterceptedSimpleBindRequest,
                 InMemoryInterceptedSimpleBindResult
{
  // The bind result for this operation.
  private BindResult bindResult;

  // The bind request for this operation.
  private SimpleBindRequest bindRequest;



  /**
   * Creates a new instance of this simple bind operation object with the
   * provided information.
   *
   * @param  clientConnection  The client connection with which this operation
   *                           is associated.
   * @param  messageID         The message ID for the associated operation.
   * @param  requestOp         The bind request protocol op in the request
   *                           received from the client.
   * @param  requestControls   The controls in the request received from the
   *                           client.
   */
  InterceptedSimpleBindOperation(
       final LDAPListenerClientConnection clientConnection, final int messageID,
       final BindRequestProtocolOp requestOp, final Control... requestControls)
  {
    super(clientConnection, messageID);

    bindRequest = (SimpleBindRequest) requestOp.toBindRequest(requestControls);
    bindResult  = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SimpleBindRequest getRequest()
  {
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setRequest(final SimpleBindRequest bindRequest)
  {
    this.bindRequest = bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public BindResult getResult()
  {
    return bindResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setResult(final BindResult bindResult)
  {
    this.bindResult = bindResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("InterceptedSimpleBindOperation(");
    appendCommonToString(buffer);
    buffer.append(", request=");
    buffer.append(bindRequest);
    buffer.append(", result=");
    buffer.append(bindResult);
    buffer.append(')');
  }
}
