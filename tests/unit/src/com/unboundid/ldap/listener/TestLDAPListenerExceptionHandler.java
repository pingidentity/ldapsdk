/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;

import com.unboundid.ldap.sdk.LDAPException;



/**
 * This class provides an implementation of the
 * {@code LDAPListenerExceptionHandler} interface that may be used for testing
 * purposes.
 */
public final class TestLDAPListenerExceptionHandler
       implements LDAPListenerExceptionHandler
{
  // The counter used to keep track of the number of connection creation
  // failures with a socket.
  private final AtomicInteger connectionCreationFailuresWithSocket;

  // The counter used to keep track of the number of connection creation
  // failures without a socket.
  private final AtomicInteger connectionCreationFailuresWithoutSocket;

  // The counter used to keep track of the number of connections closed by an
  // exception.
  private final AtomicInteger connectionsClosedByException;



  /**
   * Creates a new instance of this class.
   */
  public TestLDAPListenerExceptionHandler()
  {
    connectionCreationFailuresWithSocket    = new AtomicInteger(0);
    connectionCreationFailuresWithoutSocket = new AtomicInteger(0);
    connectionsClosedByException            = new AtomicInteger(0);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void connectionCreationFailure(final Socket socket,
                                        final Throwable cause)
  {
    if (socket == null)
    {
      connectionCreationFailuresWithoutSocket.incrementAndGet();
    }
    else
    {
      connectionCreationFailuresWithSocket.incrementAndGet();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void connectionTerminated(
                   final LDAPListenerClientConnection connection,
                   final LDAPException cause)
  {
    connectionsClosedByException.incrementAndGet();
  }



  /**
   * Retrieves the number of failures encountered while trying to create a
   * connection in which no socket was provided.
   *
   * @return  The number of failures encountered while trying to create a
   *          connection in which no socket was provided.
   */
  public int getConnectionCreationFailuresWithoutSocket()
  {
    return connectionCreationFailuresWithoutSocket.get();
  }



  /**
   * Retrieves the number of failures encountered while trying to create a
   * connection in which a socket was provided.
   *
   * @return  The number of failures encountered while trying to create a
   *          connection in which a socket was provided.
   */
  public int getConnectionCreationFailuresWithSocket()
  {
    return connectionCreationFailuresWithSocket.get();
  }



  /**
   * Retrieves the number of failures encountered while trying to create a
   * connection in which no socket was provided.
   *
   * @return  The number of failures encountered while trying to create a
   *          connection in which no socket was provided.
   */
  public int getConnectionsClosedByException()
  {
    return connectionsClosedByException.get();
  }
}
