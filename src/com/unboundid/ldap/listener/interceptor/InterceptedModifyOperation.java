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
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ReadOnlyModifyRequest;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used in the course of
 * processing a modify operation via the {@link InMemoryOperationInterceptor}
 * API.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
final class InterceptedModifyOperation
      extends InterceptedOperation
      implements InMemoryInterceptedModifyRequest,
                 InMemoryInterceptedModifyResult
{
  // The modify request for this operation.
  private ModifyRequest modifyRequest;

  // The modify result for this operation.
  private LDAPResult modifyResult;



  /**
   * Creates a new instance of this modify operation object with the provided
   * information.
   *
   * @param  clientConnection  The client connection with which this operation
   *                           is associated.
   * @param  messageID         The message ID for the associated operation.
   * @param  requestOp         The modify request protocol op in the request
   *                           received from the client.
   * @param  requestControls   The controls in the request received from the
   *                           client.
   */
  InterceptedModifyOperation(
       final LDAPListenerClientConnection clientConnection, final int messageID,
       final ModifyRequestProtocolOp requestOp,
       final Control... requestControls)
  {
    super(clientConnection, messageID);

    modifyRequest = requestOp.toModifyRequest(requestControls);
    modifyResult  = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ReadOnlyModifyRequest getRequest()
  {
    return modifyRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setRequest(final ModifyRequest modifyRequest)
  {
    this.modifyRequest = modifyRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult getResult()
  {
    return modifyResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setResult(final LDAPResult modifyResult)
  {
    this.modifyResult = modifyResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("InterceptedModifyOperation(");
    appendCommonToString(buffer);
    buffer.append(", request=");
    buffer.append(modifyRequest);
    buffer.append(", result=");
    buffer.append(modifyResult);
    buffer.append(')');
  }
}
