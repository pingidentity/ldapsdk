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



import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * Tests the behavior of the {@code WriteWithTimeout} class.
 */
public final class WriteWithTimeoutTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code WriteWithTimeout} class when a socket is available to the
   * {@code WriteWithTimeout} instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSocketWriteWithTimeout()
         throws Exception
  {
    final ServerSocket serverSocket = new ServerSocket(0);
    final int serverSocketPort = serverSocket.getLocalPort();

    final WriteWithTimeoutAcceptThread acceptThread =
         new WriteWithTimeoutAcceptThread(serverSocket);
    acceptThread.start();

    final Socket clientSocket = new Socket("localhost", serverSocketPort);
    final OutputStream outputStream = clientSocket.getOutputStream();

    WriteWithTimeout.write(outputStream, clientSocket, 0, false, 1000L);
    WriteWithTimeout.write(outputStream, clientSocket, 0, true, 1000L);

    final byte[] dataToWrite = new byte[1024];
    WriteWithTimeout.write(outputStream, clientSocket, dataToWrite, false,
         1000L);
    WriteWithTimeout.write(outputStream, clientSocket, dataToWrite, true,
         1000L);

    WriteWithTimeout.write(outputStream, clientSocket, null, 0, 0, false,
         1000L);
    WriteWithTimeout.write(outputStream, clientSocket, dataToWrite, 0, 0, false,
         1000L);
    WriteWithTimeout.write(outputStream, clientSocket, dataToWrite, false, 0L);
    WriteWithTimeout.write(outputStream, clientSocket, dataToWrite, true, 0L);

    final long stopRunningTime = System.currentTimeMillis() + 60_000L;
    int numWrites = 0;
    while (System.currentTimeMillis() < stopRunningTime)
    {
      final long startTime = System.currentTimeMillis();
      try
      {
        WriteWithTimeout.write(outputStream, clientSocket, dataToWrite, true,
             1000L);
        numWrites++;
      }
      catch (final IOException e)
      {
        assertTrue(numWrites > 0);

        final long elapsedTime = System.currentTimeMillis() - startTime;
        assertTrue(elapsedTime >= 1000L);

        return;
      }
    }

    fail("Did not get the expected IOException when trying to write with a " +
         "blocked writer");
  }



  /**
   * Tests the {@code WriteWithTimeout} class when no socket is available to the
   * {@code WriteWithTimeout} instance (although the output stream itself will
   * have a socket).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoAvailableSocketWriteWithTimeout()
         throws Exception
  {
    final ServerSocket serverSocket = new ServerSocket(0);
    final int serverSocketPort = serverSocket.getLocalPort();

    final WriteWithTimeoutAcceptThread acceptThread =
         new WriteWithTimeoutAcceptThread(serverSocket);
    acceptThread.start();

    final Socket clientSocket = new Socket("localhost", serverSocketPort);
    final OutputStream outputStream = clientSocket.getOutputStream();

    WriteWithTimeout.write(outputStream, 0, false, 1000L);
    WriteWithTimeout.write(outputStream, 0, true, 1000L);

    final byte[] dataToWrite = new byte[1024];
    WriteWithTimeout.write(outputStream, dataToWrite, false, 1000L);
    WriteWithTimeout.write(outputStream, dataToWrite, true, 1000L);

    WriteWithTimeout.write(outputStream, null, 0, 0, false, 1000L);
    WriteWithTimeout.write(outputStream, dataToWrite, 0, 0, false, 1000L);
    WriteWithTimeout.write(outputStream, dataToWrite, false, 0L);
    WriteWithTimeout.write(outputStream, dataToWrite, true, 0L);

    final long stopRunningTime = System.currentTimeMillis() + 60_000L;
    int numWrites = 0;
    while (System.currentTimeMillis() < stopRunningTime)
    {
      final long startTime = System.currentTimeMillis();
      try
      {
        WriteWithTimeout.write(outputStream, dataToWrite, true, 1000L);
        numWrites++;
      }
      catch (final IOException e)
      {
        assertTrue(numWrites > 0);

        final long elapsedTime = System.currentTimeMillis() - startTime;
        assertTrue(elapsedTime >= 1000L);

        return;
      }
    }

    fail("Did not get the expected IOException when trying to write with a " +
         "blocked writer");
  }
}
