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



import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ReadOnlyModifyDNRequest;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an API that can be used in the course of processing a
 * modify DN request via the {@link InMemoryOperationInterceptor} API.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface InMemoryInterceptedModifyDNResult
       extends InMemoryInterceptedResult
{
  /**
   * Retrieves the modify DN request that was processed.  If the request was
   * altered between the time it was received from the client and the time it
   * was actually processed by the in-memory directory server, then this will be
   * the most recently altered version.
   *
   * @return  The modify DN request that was processed.
   */
  @NotNull()
  ReadOnlyModifyDNRequest getRequest();



  /**
   * Retrieves the modify DN result to be returned to the client.
   *
   * @return  The modify DN result to be returned to the client.
   */
  @Nullable()
  LDAPResult getResult();



  /**
   * Replaces the modify DN result to be returned to the client.
   *
   * @param  modifyDNResult  The modify DN result that should be returned to the
   *                         client instead of the result originally generated
   *                         by the in-memory directory server.  It must not be
   *                         {@code null}.
   */
  void setResult(@NotNull LDAPResult modifyDNResult);



  /**
   * Sends the provided intermediate response message to the client.  It will
   * be processed by the
   * {@link InMemoryOperationInterceptor#processIntermediateResponse} method of
   * all registered operation interceptors.
   *
   * @param  intermediateResponse  The intermediate response to send to the
   *                               client.  It must not be {@code null}.
   *
   * @throws  LDAPException  If a problem is encountered while trying to send
   *                         the intermediate response.
   */
  void sendIntermediateResponse(
            @NotNull IntermediateResponse intermediateResponse)
       throws LDAPException;
}
