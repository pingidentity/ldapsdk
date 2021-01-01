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



import com.unboundid.ldap.sdk.LDAPException;

import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that may be used to intercept and potentially alter
 * communication between an LDAP client and the in-memory directory server.  An
 * operation interceptor may be enabled for use with the in-memory directory
 * server by registering it with the
 * {@link com.unboundid.ldap.listener.InMemoryDirectoryServerConfig}.  The
 * default implementation of all methods defined in this class is to return the
 * provided request or result without altering it in any way.
 * <BR><BR>
 * Note that any operation interceptors configured for use will be invoked only
 * for requests received via LDAP.  Operations processed via method calls made
 * directly to the {@link com.unboundid.ldap.listener.InMemoryDirectoryServer}
 * class via the {@link com.unboundid.ldap.sdk.LDAPInterface} interface will not
 * cause any operation interceptors to be invoked.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class InMemoryOperationInterceptor
{
  /**
   * Invokes any processing that should be performed for the provided add
   * request before it is passed to the in-memory directory server.
   *
   * @param  request  Information about the request that was received from the
   *                  client.
   *
   * @throws  LDAPException  If the provided operation should not be passed onto
   *                         the in-memory directory server, but the result
   *                         represented by this exception should be used
   *                         instead.
   */
  public void processAddRequest(
                   @NotNull final InMemoryInterceptedAddRequest request)
         throws LDAPException
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided add result
   * before it is returned to the client.
   *
   * @param  result  Information about the add result that is to be returned to
   *                 the client.
   */
  public void processAddResult(
                   @NotNull final InMemoryInterceptedAddResult result)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided simple
   * bind request before it is passed to the in-memory directory server.
   *
   * @param  request  Information about the request that was received from the
   *                  client.
   *
   * @throws  LDAPException  If the provided operation should not be passed onto
   *                         the in-memory directory server, but the result
   *                         represented by this exception should be used
   *                         instead.
   */
  public void processSimpleBindRequest(
                   @NotNull final InMemoryInterceptedSimpleBindRequest request)
         throws LDAPException
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided simple
   * bind result before it is returned to the client.
   *
   * @param  result  Information about the bind result that is to be returned to
   *                 the client.
   */
  public void processSimpleBindResult(
                   @NotNull final InMemoryInterceptedSimpleBindResult result)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided SASL bind
   * request before it is passed to the in-memory directory server.
   *
   * @param  request  Information about the request that was received from the
   *                  client.
   *
   * @throws  LDAPException  If the provided operation should not be passed onto
   *                         the in-memory directory server, but the result
   *                         represented by this exception should be used
   *                         instead.
   */
  public void processSASLBindRequest(
                   @NotNull final InMemoryInterceptedSASLBindRequest request)
         throws LDAPException
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided SASL bind
   * result before it is returned to the client.
   *
   * @param  result  Information about the bind result that is to be returned to
   *                 the client.
   */
  public void processSASLBindResult(
                   @NotNull final InMemoryInterceptedSASLBindResult result)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided compare
   * request before it is passed to the in-memory directory server.
   *
   * @param  request  Information about the request that was received from the
   *                  client.
   *
   * @throws  LDAPException  If the provided operation should not be passed onto
   *                         the in-memory directory server, but the result
   *                         represented by this exception should be used
   *                         instead.
   */
  public void processCompareRequest(
                   @NotNull final InMemoryInterceptedCompareRequest request)
         throws LDAPException
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided compare
   * result before it is returned to the client.
   *
   * @param  result  Information about the compare result that is to be returned
   *                 to the client.
   */
  public void processCompareResult(
                   @NotNull final InMemoryInterceptedCompareResult result)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided delete
   * request before it is passed to the in-memory directory server.
   *
   * @param  request  Information about the request that was received from the
   *                  client.
   *
   * @throws  LDAPException  If the provided operation should not be passed onto
   *                         the in-memory directory server, but the result
   *                         represented by this exception should be used
   *                         instead.
   */
  public void processDeleteRequest(
                   @NotNull final InMemoryInterceptedDeleteRequest request)
         throws LDAPException
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided delete
   * result before it is returned to the client.
   *
   * @param  result  Information about the delete result that is to be returned
   *                 to the client.
   */
  public void processDeleteResult(
                   @NotNull final InMemoryInterceptedDeleteResult result)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided extended
   * request before it is passed to the in-memory directory server.
   *
   * @param  request  Information about the request that was received from the
   *                  client.
   *
   * @throws  LDAPException  If the provided operation should not be passed onto
   *                         the in-memory directory server, but the result
   *                         represented by this exception should be used
   *                         instead.
   */
  public void processExtendedRequest(
                   @NotNull final InMemoryInterceptedExtendedRequest request)
         throws LDAPException
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided extended
   * result before it is returned to the client.
   *
   * @param  result  Information about the extended result that is to be
   *                 returned to the client.
   */
  public void processExtendedResult(
                   @NotNull final InMemoryInterceptedExtendedResult result)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided modify
   * request before it is passed to the in-memory directory server.
   *
   * @param  request  Information about the request that was received from the
   *                  client.
   *
   * @throws  LDAPException  If the provided operation should not be passed onto
   *                         the in-memory directory server, but the result
   *                         represented by this exception should be used
   *                         instead.
   */
  public void processModifyRequest(
                   @NotNull final InMemoryInterceptedModifyRequest request)
         throws LDAPException
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided modify
   * result before it is returned to the client.
   *
   * @param  result  Information about the modify result that is to be returned
   *                 to the client.
   */
  public void processModifyResult(
                   @NotNull final InMemoryInterceptedModifyResult result)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided modify DN
   * request before it is passed to the in-memory directory server.
   *
   * @param  request  Information about the request that was received from the
   *                  client.
   *
   * @throws  LDAPException  If the provided operation should not be passed onto
   *                         the in-memory directory server, but the result
   *                         represented by this exception should be used
   *                         instead.
   */
  public void processModifyDNRequest(
                   @NotNull final InMemoryInterceptedModifyDNRequest request)
         throws LDAPException
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided modify DN
   * result before it is returned to the client.
   *
   * @param  result  Information about the modify DN result that is to be
   *                 returned to the client.
   */
  public void processModifyDNResult(
                   @NotNull final InMemoryInterceptedModifyDNResult result)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided search
   * request before it is passed to the in-memory directory server.
   *
   * @param  request  Information about the request that was received from the
   *                  client.
   *
   * @throws  LDAPException  If the provided operation should not be passed onto
   *                         the in-memory directory server, but the result
   *                         represented by this exception should be used
   *                         instead.
   */
  public void processSearchRequest(
                   @NotNull final InMemoryInterceptedSearchRequest request)
         throws LDAPException
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided search
   * result entry before it is returned to the client.
   *
   * @param  entry  Information about the search result entry to be returned.
   */
  public void processSearchEntry(
                   @NotNull final InMemoryInterceptedSearchEntry entry)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided search
   * result reference before it is returned to the client.
   *
   * @param  reference  Information about the search result reference to be
   *                    returned.
   */
  public void processSearchReference(
                   @NotNull final InMemoryInterceptedSearchReference reference)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided search
   * result before it is returned to the client.
   *
   * @param  result  Information about the search result that is to be returned
   *                 to the client.
   */
  public void processSearchResult(
                   @NotNull final InMemoryInterceptedSearchResult result)
  {
    // No processing will be performed by default.
  }



  /**
   * Invokes any processing that should be performed for the provided
   * intermediate response before it is returned to the client.
   *
   * @param  response  Information about the intermediate response to be
   *                   returned to the client.
   */
  public void processIntermediateResponse(
       @NotNull final InMemoryInterceptedIntermediateResponse response)
  {
    // No processing will be performed by default.
  }
}
