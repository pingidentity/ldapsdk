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
import java.net.ServerSocket;
import javax.net.ServerSocketFactory;



/**
 * This class provides a {@code ServerSocketFactory} implementation that will
 * create server sockets that will throw an exception on every attempt to accept
 * a socket.
 */
public final class ThrowsOnAcceptServerSocketFactory
       extends ServerSocketFactory
{
  /**
   * Creates a new instance of this server socket factory that will return
   * sockets that throw an exception on every attempt to accept a connection.
   */
  public ThrowsOnAcceptServerSocketFactory()
  {
  }



  /**
   * Creates a new unbound server socket.
   *
   * @return  The created server socket.
   *
   * @throws  IOException If a problem occurs.
   */
  @Override()
  public ServerSocket createServerSocket()
         throws IOException
  {
    return new ThrowsOnAcceptServerSocket();
  }



  /**
   * Creates a new server socket configured to listen on the specified port.
   *
   * @param  port  The port on which to listen for connections.
   *
   * @return  The created server socket.
   *
   * @throws  IOException If a problem occurs.
   */
  @Override()
  public ServerSocket createServerSocket(final int port)
         throws IOException
  {
    return new ThrowsOnAcceptServerSocket(port);
  }



  /**
   * Creates a new server socket configured to listen on the specified port.
   *
   * @param  port     The port on which to listen for connections.
   * @param  backlog  The backlog to use when accepting connections.
   *
   * @return  The created server socket.
   *
   * @throws  IOException If a problem occurs.
   */
  @Override()
  public ServerSocket createServerSocket(final int port, final int backlog)
         throws IOException
  {
    return new ThrowsOnAcceptServerSocket(port, backlog);
  }



  /**
   * Creates a new server socket configured to listen on the specified port.
   *
   * @param  port       The port on which to listen for connections.
   * @param  backlog    The backlog to use when accepting connections.
   * @param  ifAddress  The address on which to listen for connections.
   *
   * @return  The created server socket.
   *
   * @throws  IOException If a problem occurs.
   */
  @Override()
  public ServerSocket createServerSocket(final int port, final int backlog,
                                         final InetAddress ifAddress)
         throws IOException
  {
    return new ThrowsOnAcceptServerSocket(port, backlog, ifAddress);
  }
}
