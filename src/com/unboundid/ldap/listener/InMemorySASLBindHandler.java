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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that may be used to provide support for a specified
 * SASL mechanism in the in-memory directory server.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class InMemorySASLBindHandler
{
  /**
   * Retrieves the name of the SASL mechanism supported by this bind handler.
   *
   * @return  The name of the SASL mechanism supported by this bind handler.
   */
  @NotNull()
  public abstract String getSASLMechanismName();



  /**
   * Performs the appropriate processing for a SASL bind request with the
   * provided information.
   * <BR><BR>
   * If the bind processing is successful, then this method should also call
   * {@link InMemoryRequestHandler#setAuthenticatedDN(DN)} on the provided
   * request handler instance to set the identity of the authenticated user.
   * <BR><BR>
   * If the associated SASL mechanism requires multiple stages of processing
   * and it is necessary to store and retrieve state information to use in other
   * stages of the bind processing, then the map returned by the
   * {@link InMemoryRequestHandler#getConnectionState()} method should be used
   * for this purpose.
   *
   * @param  handler      The in-memory request handler that accepted the bind
   *                      request.
   * @param  messageID    The message ID for the LDAP message that the client
   *                      used to send the request.
   * @param  bindDN       The bind DN provided by the client.
   * @param  credentials  The SASL credentials provided by the client, or
   *                      {@code null} if there were none.
   * @param  controls     The request controls provided by the client.
   *
   * @return  The result that should be returned to the client in response to
   *          the provided request.
   */
  @NotNull()
  public abstract BindResult processSASLBind(
                                  @NotNull InMemoryRequestHandler handler,
                                  int messageID, @NotNull DN bindDN,
                                  @Nullable ASN1OctetString credentials,
                                  @NotNull List<Control> controls);



  /**
   * Retrieves a string representation of this SASL bind handler.
   *
   * @return  A string representation of this SASL bind handler.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return "InMemorySASLBindHandler(mechanismName='" + getSASLMechanismName() +
         ')';
  }
}
