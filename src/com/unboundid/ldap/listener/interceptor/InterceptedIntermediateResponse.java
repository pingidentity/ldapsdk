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



import com.unboundid.ldap.protocol.IntermediateResponseProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used in the course of
 * processing an intermediate response returned for an operation via the
 * {@link InMemoryOperationInterceptor} API.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
final class InterceptedIntermediateResponse
      extends InterceptedOperation
      implements InMemoryInterceptedIntermediateResponse
{
  // The associated operation.
  @NotNull private final InterceptedOperation op;

  // The intermediate response to be processed.
  @Nullable private IntermediateResponse response;



  /**
   * Creates a new instance of this search entry object with the provided
   * information.
   *
   * @param  op                The operation being processed.
   * @param  response          The intermediate response to be processed.
   * @param  responseControls  The set of controls included in the response.
   */
  InterceptedIntermediateResponse(@NotNull final InterceptedOperation op,
       @NotNull final IntermediateResponseProtocolOp response,
       @Nullable final Control... responseControls)
  {
    super(op);

    this.op = op;
    this.response = response.toIntermediateResponse(responseControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public InMemoryInterceptedRequest getRequest()
  {
    return op;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public IntermediateResponse getIntermediateResponse()
  {
    return response;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setIntermediateResponse(
                   @Nullable final IntermediateResponse response)
  {
    this.response = response;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("InterceptedIntermediateResponse(");
    buffer.append("op=");
    buffer.append(op);
    buffer.append(", response=");
    buffer.append(response);
    buffer.append(')');
  }
}
