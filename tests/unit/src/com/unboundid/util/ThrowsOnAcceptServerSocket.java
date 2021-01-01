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
package com.unboundid.util;



import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;



/**
 * This class provides a {@code ServerSocket} implementation that will throw
 * an exception whenever an attempt is made to accept a new connection.
 */
public final class ThrowsOnAcceptServerSocket
       extends ServerSocket
{
  /**
   * Creates a new unbound server socket.
   *
   * @throws  IOException  If an unexpected problem occurs.
   */
  public ThrowsOnAcceptServerSocket()
         throws IOException
  {
    super();
  }



  /**
   * Creates a new server socket to listen on the specified port.
   *
   * @param  port  The port on which to listen for connections.
   *
   * @throws  IOException  If an unexpected problem occurs.
   */
  public ThrowsOnAcceptServerSocket(final int port)
         throws IOException
  {
    super(port);
  }



  /**
   * Creates a new server socket to listen on the specified port.
   *
   * @param  port     The port on which to listen for connections.
   * @param  backlog  The accept backlog to use.
   *
   * @throws  IOException  If an unexpected problem occurs.
   */
  public ThrowsOnAcceptServerSocket(final int port, final int backlog)
         throws IOException
  {
    super(port, backlog);
  }



  /**
   * Creates a new server socket to listen on the specified port.
   *
   * @param  port           The port on which to listen for connections.
   * @param  backlog        The accept backlog to use.
   * @param  listenAddress  The address on which to listen for connections.
   *
   * @throws  IOException  If an unexpected problem occurs.
   */
  public ThrowsOnAcceptServerSocket(final int port, final int backlog,
                                    final InetAddress listenAddress)
         throws IOException
  {
    super(port, backlog, listenAddress);
  }



  /**
   * Accepts a new connection from a client.  This method will always throw an
   * exception.
   *
   * @return  The connection that was accepted.  This will never happen.
   *
   * @throws  IOException  Always.
   */
  @Override()
  public Socket accept()
         throws IOException
  {
    throw new IOException("accept failure");
  }
}
