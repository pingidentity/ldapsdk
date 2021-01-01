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
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ReadOnlyCompareRequest;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used in the course of
 * processing a compare operation via the {@link InMemoryOperationInterceptor}
 * API.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
final class InterceptedCompareOperation
      extends InterceptedOperation
      implements InMemoryInterceptedCompareRequest,
                 InMemoryInterceptedCompareResult
{
  // The compare request for this operation.
  @NotNull private CompareRequest compareRequest;

  // The compare result for this operation.
  @Nullable private LDAPResult compareResult;



  /**
   * Creates a new instance of this compare operation object with the provided
   * information.
   *
   * @param  clientConnection  The client connection with which this operation
   *                           is associated.
   * @param  messageID         The message ID for the associated operation.
   * @param  requestOp         The compare request protocol op in the request
   *                           received from the client.
   * @param  requestControls   The controls in the request received from the
   *                           client.
   */
  InterceptedCompareOperation(
       @NotNull final LDAPListenerClientConnection clientConnection,
       final int messageID, @NotNull final CompareRequestProtocolOp requestOp,
       @Nullable final Control... requestControls)
  {
    super(clientConnection, messageID);

    compareRequest = requestOp.toCompareRequest(requestControls);
    compareResult  = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ReadOnlyCompareRequest getRequest()
  {
    return compareRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setRequest(@NotNull final CompareRequest compareRequest)
  {
    this.compareRequest = compareRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public LDAPResult getResult()
  {
    return compareResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setResult(@NotNull final LDAPResult compareResult)
  {
    this.compareResult = compareResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("InterceptedCompareOperation(");
    appendCommonToString(buffer);
    buffer.append(", request=");
    buffer.append(compareRequest);
    buffer.append(", result=");
    buffer.append(compareResult);
    buffer.append(')');
  }
}
