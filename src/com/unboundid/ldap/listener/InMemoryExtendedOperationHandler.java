/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.util.List;

import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that may be used to provide support for one or
 * more types of extended operations in the in-memory directory server.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class InMemoryExtendedOperationHandler
{
  /**
   * Retrieves the name that should be used for this extended operation handler.
   *
   * @return  The name that should be used for this extended operation handler.
   */
  @NotNull()
  public abstract String getExtendedOperationHandlerName();



  /**
   * Retrieves a list of the extended request OIDs supported by this extended
   * operation handler.
   *
   * @return  A list of the extended request OIDs supported by this extended
   *          operation handler.
   */
  @NotNull()
  public abstract List<String> getSupportedExtendedRequestOIDs();



  /**
   * Performs the appropriate processing for the provided extended request.
   * This method is completely responsible for any controls associated with the
   * provided request.
   *
   * @param  handler    The in-memory request handler that accepted the extended
   *                    request.
   * @param  messageID  The message ID for the LDAP message that the client used
   *                    to send the request.
   * @param  request    The extended request to process, which will have a
   *                    request OID which matches one of the OIDs in the list
   *                    returned byt the
   *                    {@link #getSupportedExtendedRequestOIDs()} method.
   *
   * @return  The result that should be returned to the client in response to
   *          the provided request.
   */
  @NotNull()
  public abstract ExtendedResult processExtendedOperation(
                                      @NotNull InMemoryRequestHandler handler,
                                      int messageID,
                                      @NotNull ExtendedRequest request);



  /**
   * Retrieves a string representation of this extended operation handler.
   *
   * @return  A string representation of this extended operation handler.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return getExtendedOperationHandlerName();
  }
}
