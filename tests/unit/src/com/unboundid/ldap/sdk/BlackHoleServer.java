/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;



/**
 * This class provides a TCP server that will accept connections but will not
 * ever read any data from them.  If a client sends enough data to the server,
 * then it will eventually fill up the server's receive queue and then the
 * client's send queue, which means that subsequent write attempts will block.
 */
public final class BlackHoleServer
       extends Thread
{
  // A list that will hold all of the connections that have been established.
  private final List<Socket> clientSockets;

  // The server socket that will be used to accept new connections.
  private final ServerSocket serverSocket;



  /**
   * Creates a new black hole server.
   *
   * @param  listenPort  The port on which the server should listen for
   *                     connections.  A value of zero indicates that the server
   *                     should automatically choose a free port.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  public BlackHoleServer(final int listenPort)
         throws Exception
  {
    clientSockets = new ArrayList<>(10);
    serverSocket = new ServerSocket(listenPort);
  }



  /**
   * Retrieves the port on which the server is listening.
   *
   * @return  The port on which the server is listening.
   */
  public int getListenPort()
  {
    return serverSocket.getLocalPort();
  }



  /**
   * Operates in a loop, accepting connections and putting them into a list,
   * but then completely ignoring them.  This will continue until an error
   * occurs, at which time any existing connections will be closed.
   */
  @Override()
  public void run()
  {
    while (true)
    {
      try
      {
        final Socket clientSocket = serverSocket.accept();
        clientSockets.add(clientSocket);
      }
      catch (final Exception e)
      {
        break;
      }
    }

    for (final Socket s : clientSockets)
    {
      try
      {
        s.close();
      }
      catch (final Exception e)
      {
        // No action is required.
      }
    }
  }



  /**
   * Shuts down this server.
   */
  public void shutDown()
  {
    try
    {
      serverSocket.close();
    }
    catch (final Exception e)
    {
      // No action is required.
    }
  }
}
