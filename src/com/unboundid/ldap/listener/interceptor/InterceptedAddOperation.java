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
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ReadOnlyAddRequest;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used in the course of
 * processing an add operation via the {@link InMemoryOperationInterceptor} API.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
final class InterceptedAddOperation
      extends InterceptedOperation
      implements InMemoryInterceptedAddRequest, InMemoryInterceptedAddResult
{
  // The add request for this operation.
  private AddRequest addRequest;

  // The add result for this operation.
  private LDAPResult addResult;



  /**
   * Creates a new instance of this add operation object with the provided
   * information.
   *
   * @param  clientConnection  The client connection with which this operation
   *                           is associated.
   * @param  messageID         The message ID for the associated operation.
   * @param  requestOp         The add request protocol op in the request
   *                           received from the client.
   * @param  requestControls   The controls in the request received from the
   *                           client.
   */
  InterceptedAddOperation(final LDAPListenerClientConnection clientConnection,
                          final int messageID,
                          final AddRequestProtocolOp requestOp,
                          final Control... requestControls)
  {
    super(clientConnection, messageID);

    addRequest = requestOp.toAddRequest(requestControls);
    addResult  = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ReadOnlyAddRequest getRequest()
  {
    return addRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setRequest(final AddRequest addRequest)
  {
    this.addRequest = addRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult getResult()
  {
    return addResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setResult(final LDAPResult addResult)
  {
    this.addResult = addResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("InterceptedAddOperation(");
    appendCommonToString(buffer);
    buffer.append(", request=");
    buffer.append(addRequest);
    buffer.append(", result=");
    buffer.append(addResult);
    buffer.append(')');
  }
}
