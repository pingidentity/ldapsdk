/*
 * Copyright 2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019 Ping Identity Corporation
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



import java.net.ServerSocket;
import java.net.Socket;



/**
 * This class provides a background thread that can accept a client connection
 * on a provided server socket, and then hold onto that socket while not
 * reading any data from it.  This will eventually cause the receive buffer to
 * become full, followed by the send buffer on the other end of the connection,
 * at which point attempts to write to the socket will block.
 */
final class WriteWithTimeoutAcceptThread
      extends Thread
{
  // Indicates whether this thread has been requested to stop.
  private volatile boolean stopRequested;

  // The server socket that will be
  private final ServerSocket serverSocket;



  /**
   * Creates a new instance of this accept thread that will use the provided
   * server socket.
   *
   * @param  serverSocket  The server socket that will be used to accept a
   *                       connection.
   */
  WriteWithTimeoutAcceptThread(final ServerSocket serverSocket)
  {
    setName("WriteWithTimeoutAcceptThread");
    setDaemon(true);

    this.serverSocket = serverSocket;
    stopRequested = false;
  }



  /**
   * Uses the server socket to accept a client connection, then sleeps until a
   * signal is received to stop running.
   */
  @Override()
  public void run()
  {
    try
    {
      final Socket clientSocket = serverSocket.accept();

      while (! stopRequested)
      {
        Thread.sleep(1L);
      }

      clientSocket.close();
      serverSocket.close();
    }
    catch (final Exception e)
    {
      // No implementation required.
    }
  }
}
