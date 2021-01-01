/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.util.Arrays;
import java.util.List;

import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides an implementation of an extended operation handler that
 * can return a canned response to an extended request with a specified OID.
 */
public final class CannedResponseExtendedOperationHandler
       extends InMemoryExtendedOperationHandler
{
  // The canned result that will be returned for all requests.
  private final ExtendedResult result;

  // The OIDs that this extended operation handler is able to process.
  private final List<String> oids;



  /**
   * Creates a new canned response extended operation handler that will return
   * a success result for all requests with one of the given OIDs.
   *
   * @param  oids  The set of extended operation OIDs to be registered.
   */
  public CannedResponseExtendedOperationHandler(final String... oids)
  {
    this(ResultCode.SUCCESS, oids);
  }



  /**
   * Creates a new canned response extended operation handler that will return
   * a success result for all requests with one of the given OIDs.
   *
   * @param  resultCode  The result code to return for all extended operations.
   * @param  oids        The set of extended operation OIDs to be registered.
   */
  public CannedResponseExtendedOperationHandler(final ResultCode resultCode,
                                                final String... oids)
  {
    this(new ExtendedResult(-1, resultCode, null, null, null, null, null, null),
         oids);
  }



  /**
   * Creates a new canned response extended operation handler that will return
   * the provided result for all requests with one of the given OIDs.
   *
   * @param  result  The result to return for all extended operations.
   * @param  oids    The set of extended operation OIDs to be registered.
   */
  public CannedResponseExtendedOperationHandler(final ExtendedResult result,
                                                final String... oids)
  {
    this.result = result;
    this.oids = Arrays.asList(oids);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedOperationHandlerName()
  {
    return "Canned Response Extended Operation Handler";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return oids;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult processExtendedOperation(
                             final InMemoryRequestHandler handler,
                             final int messageID,
                             final ExtendedRequest request)
  {
    return new ExtendedResult(messageID, result.getResultCode(),
         result.getDiagnosticMessage(), result.getMatchedDN(),
         result.getReferralURLs(), result.getOID(), result.getValue(),
         result.getResponseControls());
  }
}
