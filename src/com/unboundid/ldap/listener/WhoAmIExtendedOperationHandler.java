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



import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides an implementation of an extended operation handler for
 * the in-memory directory server that can be used to process the "Who Am I?"
 * extended operation as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc4532.txt">RFC 4532</A>.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class WhoAmIExtendedOperationHandler
       extends InMemoryExtendedOperationHandler
{
  /**
   * Creates a new instance of this extended operation handler.
   */
  public WhoAmIExtendedOperationHandler()
  {
    // No initialization is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedOperationHandlerName()
  {
    return "Who Am I?";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return Collections.singletonList(
         WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ExtendedResult processExtendedOperation(
              @NotNull final InMemoryRequestHandler handler,
              final int messageID,
              @NotNull final ExtendedRequest request)
  {
    // This extended operation handler does not support any controls.  If the
    // request has any critical controls, then reject it.
    for (final Control c : request.getControls())
    {
      if (c.isCritical())
      {
        return new ExtendedResult(messageID,
             ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
             ERR_WHO_AM_I_EXTOP_UNSUPPORTED_CONTROL.get(c.getOID()), null, null,
             null, null, null);
      }
    }

    final String authorizationID =
         "dn:" + handler.getAuthenticatedDN().toString();
    return new WhoAmIExtendedResult(messageID, ResultCode.SUCCESS,  null,
         null, null, authorizationID, null);
  }
}
