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



import java.net.InetAddress;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

import com.unboundid.ldap.listener.LDAPListenerClientConnection;
import com.unboundid.ldap.protocol.IntermediateResponseProtocolOp;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a base implementation for a structure that can be used in
 * the course of processing an operation via the
 * {@link InMemoryOperationInterceptor} API.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
abstract class InterceptedOperation
         implements InMemoryInterceptedRequest, InMemoryInterceptedResult
{
  // The message ID for the associated operation.
  private final int messageID;

  // The client connection associated with this operation.
  @NotNull private final LDAPListenerClientConnection clientConnection;

  // A map that may be used to hold state information for correlating
  // information between a request and a response.
  @NotNull private final Map<String,Object> propertyMap;



  /**
   * Creates a new instance of this operation object with the provided
   * information.
   *
   * @param  clientConnection  The client connection with which this operation
   *                           is associated.
   * @param  messageID         The message ID for the associated operation.
   */
  InterceptedOperation(
       @NotNull final LDAPListenerClientConnection clientConnection,
       final int messageID)
  {
    this.clientConnection = clientConnection;
    this.messageID        = messageID;

    propertyMap = new HashMap<>(StaticUtils.computeMapCapacity(10));
  }



  /**
   * Creates a new instance of this operation object using the provided
   * operation as a basis.  The new operation will share the same property map
   * as the parent operation.
   *
   * @param  operation  The operation to use to create this intercepted
   *                    operation.
   */
  InterceptedOperation(@NotNull final InterceptedOperation operation)
  {
    clientConnection = operation.clientConnection;
    messageID        = operation.messageID;
    propertyMap      = operation.propertyMap;
  }



  /**
   * Retrieves the client connection associated with this operation.
   *
   * @return  The client connection associated with this operation.
   */
  @NotNull()
  LDAPListenerClientConnection getClientConnection()
  {
    return clientConnection;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final long getConnectionID()
  {
    if (clientConnection == null)
    {
      return -1L;
    }
    else
    {
      return clientConnection.getConnectionID();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getConnectedAddress()
  {
    if (clientConnection == null)
    {
      return null;
    }

    final Socket s = clientConnection.getSocket();
    if (s == null)
    {
      return null;
    }

    final InetAddress localAddress = s.getLocalAddress();
    if (localAddress == null)
    {
      return null;
    }

    return localAddress.getHostAddress();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getConnectedPort()
  {
    if (clientConnection == null)
    {
      return -1;
    }

    final Socket s = clientConnection.getSocket();
    if (s == null)
    {
      return -1;
    }

    return s.getLocalPort();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final int getMessageID()
  {
    return messageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final void sendIntermediateResponse(
              @NotNull final IntermediateResponse intermediateResponse)
         throws LDAPException
  {
    clientConnection.sendIntermediateResponse(messageID,
         new IntermediateResponseProtocolOp(intermediateResponse),
         intermediateResponse.getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final void sendUnsolicitedNotification(
                         @NotNull final ExtendedResult unsolicitedNotification)
         throws LDAPException
  {
    clientConnection.sendUnsolicitedNotification(unsolicitedNotification);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Object getProperty(@NotNull final String name)
  {
    return propertyMap.get(name);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Object setProperty(@NotNull final String name,
                                  @Nullable final Object value)
  {
    if (value == null)
    {
      return propertyMap.remove(name);
    }
    else
    {
      return propertyMap.put(name, value);
    }
  }



  /**
   * Retrieves a string representation of this intercepted operation.
   *
   * @return  A string representation of this intercepted operation.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this intercepted operation to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public abstract void toString(@NotNull StringBuilder buffer);



  /**
   * Appends a common set of information about this intercepted operation to the
   * provided buffer.  The common information will include the connection ID and
   * message ID.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  protected final void appendCommonToString(@NotNull final StringBuilder buffer)
  {
    buffer.append("connectionID=");
    buffer.append(getConnectionID());
    buffer.append(", connectedAddress='");
    buffer.append(getConnectedAddress());
    buffer.append("', connectedPort=");
    buffer.append(getConnectedPort());
    buffer.append(", messageID=");
    buffer.append(messageID);
  }
}
