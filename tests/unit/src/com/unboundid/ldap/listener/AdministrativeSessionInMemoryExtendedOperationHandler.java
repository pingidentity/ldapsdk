/*
 * Copyright 2020-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2025 Ping Identity Corporation
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
 * Copyright (C) 2020-2025 Ping Identity Corporation
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
import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            EndAdministrativeSessionExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionExtendedRequest;



/**
 * This class provides an in-memory extended operation handler that simulates
 * support for the start and end administrative session operations.
 */
public class AdministrativeSessionInMemoryExtendedOperationHandler
       extends InMemoryExtendedOperationHandler
{
  /**
   * Creates a new instance of this extended operation handler.
   */
  public AdministrativeSessionInMemoryExtendedOperationHandler()
  {
    // No implementation is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedOperationHandlerName()
  {
    return "Administrative Session";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return Collections.unmodifiableList(Arrays.asList(
         StartAdministrativeSessionExtendedRequest.
              START_ADMIN_SESSION_REQUEST_OID,
         EndAdministrativeSessionExtendedRequest.
              END_ADMIN_SESSION_REQUEST_OID));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult processExtendedOperation(
                             final InMemoryRequestHandler handler,
                             final int messageID, final ExtendedRequest request)
  {
    return new ExtendedResult(messageID, ResultCode.SUCCESS, null, null, null,
         null, null, null);
  }
}
