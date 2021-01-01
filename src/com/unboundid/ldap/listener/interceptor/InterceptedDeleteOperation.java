/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ReadOnlyDeleteRequest;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used in the course of
 * processing a delete operation via the {@link InMemoryOperationInterceptor}
 * API.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
final class InterceptedDeleteOperation
      extends InterceptedOperation
      implements InMemoryInterceptedDeleteRequest,
                 InMemoryInterceptedDeleteResult
{
  // The delete request for this operation.
  @NotNull private DeleteRequest deleteRequest;

  // The delete result for this operation.
  @Nullable private LDAPResult deleteResult;



  /**
   * Creates a new instance of this delete operation object with the provided
   * information.
   *
   * @param  clientConnection  The client connection with which this operation
   *                           is associated.
   * @param  messageID         The message ID for the associated operation.
   * @param  requestOp         The delete request protocol op in the request
   *                           received from the client.
   * @param  requestControls   The controls in the request received from the
   *                           client.
   */
  InterceptedDeleteOperation(
       @NotNull final LDAPListenerClientConnection clientConnection,
       final int messageID, @NotNull final DeleteRequestProtocolOp requestOp,
       @Nullable final Control... requestControls)
  {
    super(clientConnection, messageID);

    deleteRequest = requestOp.toDeleteRequest(requestControls);
    deleteResult  = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ReadOnlyDeleteRequest getRequest()
  {
    return deleteRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setRequest(@NotNull final DeleteRequest deleteRequest)
  {
    this.deleteRequest = deleteRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public LDAPResult getResult()
  {
    return deleteResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setResult(@NotNull final LDAPResult deleteResult)
  {
    this.deleteResult = deleteResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("InterceptedDeleteOperation(");
    appendCommonToString(buffer);
    buffer.append(", request=");
    buffer.append(deleteRequest);
    buffer.append(", result=");
    buffer.append(deleteResult);
    buffer.append(')');
  }
}
