/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.listener.InMemoryExtendedOperationHandler;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;



/**
 * This class provides an implementation of an extended operation handler that
 * may be used in conjunction with the in-memory directory server to provide
 * fake support for the start administrative session extended operation.  It is
 * only intended for testing purposes and does not do any real processing.
 */
public final class StartAdministrativeSessionInMemoryExtendedOperationHandler
       extends InMemoryExtendedOperationHandler
{
  // The result code to use for the extended result that is returned.
  private final ExtendedResult result;



  /**
   * Creates a new instance of this extended operation handler with the provided
   * result.
   *
   * @param  result  The result that will be returned in response to an extended
   *                 operation.
   */
  public StartAdministrativeSessionInMemoryExtendedOperationHandler(
              final ExtendedResult result)
  {
    this.result = result;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedOperationHandlerName()
  {
    return "Start Administrative Session";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return Collections.singletonList(
         StartAdministrativeSessionExtendedRequest.
              START_ADMIN_SESSION_REQUEST_OID);
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
