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
package com.unboundid.ldap.sdk;



import java.net.DatagramPacket;
import java.net.DatagramSocket;



/**
 * This class provides a very simple DNS server that will use a canned response
 * and can be used to test the SRVRecordServerSet class.  The response will
 * have two servers, with user-specified port numbers.  They will both have
 * addresses of "localhost" and weights of zero, but the first will have a
 * priority of 1 and the second will have a priority of 2.
 */
final class TestDNSSRVRecordServer
      extends Thread
{
  /**
   * The bytes that comprised the canned response that will be returned.
   */
  private static final byte[] DEFAULT_RESPONSE_BYTES =
  {
    // The DNS record header (12 bytes, offset 0).
    (byte) 0x00, (byte) 0x01,  // The transaction ID.
    (byte) 0x85, (byte) 0x80,  // The response flags
    (byte) 0x00, (byte) 0x01,  // The number of questions received
    (byte) 0x00, (byte) 0x02,  // The number of answer RRs being returned
    (byte) 0x00, (byte) 0x01,  // The number of authority RRs being returned
    (byte) 0x00, (byte) 0x01,  // The number of additional RRs being returned


    // The bytes that comprise the query being answered (28 bytes, offset 12).
    (byte) 0x05, (byte) 0x5F, (byte) 0x6C, (byte) 0x64,
    (byte) 0x61, (byte) 0x70, (byte) 0x04, (byte) 0x5F,
    (byte) 0x74, (byte) 0x63, (byte) 0x70, (byte) 0x07,
    (byte) 0x65, (byte) 0x78, (byte) 0x61, (byte) 0x6D,
    (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x03,
    (byte) 0x63, (byte) 0x6F, (byte) 0x6D, (byte) 0x00,
    (byte) 0x00, (byte) 0x21, (byte) 0x00, (byte) 0x01,


    // The bytes that comprise the answer RR being returned (58 bytes,
    // offset 40).
      // The bytes for the first server in the answer (29 bytes, offset 40).
      (byte) 0xC0, (byte) 0x0C, (byte) 0x00, (byte) 0x21,
      (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x01,
      (byte) 0x51, (byte) 0x80, (byte) 0x00, (byte) 0x11,
      (byte) 0x00, (byte) 0x01, // The priority
      (byte) 0x00, (byte) 0x01, // The weight
      (byte) 0x05, (byte) 0x6D, // The port
      (byte) 0x09, (byte) 0x6c, (byte) 0x6F, (byte) 0x63,
      (byte) 0x61, (byte) 0x6C, (byte) 0x68, (byte) 0x6F,
      (byte) 0x73, (byte) 0x74, (byte) 0x00,

      // The bytes for the second server in the answer (29 bytes, offset 69).
      (byte) 0xC0, (byte) 0x0C, (byte) 0x00, (byte) 0x21,
      (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x01,
      (byte) 0x51, (byte) 0x80, (byte) 0x00, (byte) 0x11,
      (byte) 0x00, (byte) 0x02, // The priority
      (byte) 0x00, (byte) 0x01, // The weight
      (byte) 0x09, (byte) 0x55, // The port
      (byte) 0x09, (byte) 0x6c, (byte) 0x6F, (byte) 0x63,
      (byte) 0x61, (byte) 0x6C, (byte) 0x68, (byte) 0x6F,
      (byte) 0x73, (byte) 0x74, (byte) 0x00,


    // The bytes that comprise the authoritative nameserver portion of the
    // response (18 bytes, offset 98).
    (byte) 0xC0, (byte) 0x17, (byte) 0x00, (byte) 0x02,
    (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x01,
    (byte) 0x51, (byte) 0x80, (byte) 0x00, (byte) 0x06,
    (byte) 0x03, (byte) 0x64, (byte) 0x6E, (byte) 0x73,
    (byte) 0xC0, (byte) 0x17,


    // The bytes that comprise the additional records portion of the response
    // (16 bytes, offset 116).
    (byte) 0xC0, (byte) 0x6E, (byte) 0x00, (byte) 0x01,
    (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x01,
    (byte) 0x51, (byte) 0x80, (byte) 0x00, (byte) 0x04,
    (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x01
  };



  /**
   * The offset at which the transaction ID begins.
   */
  private static final int TXN_ID_OFFSET = 0;



  /**
   * The offset at which the port of the first server begins.
   */
  private static final int SERVER_1_PORT_OFFSET = 56;



  /**
   * The offset at which the port of the second server begins.
   */
  private static final int SERVER_2_PORT_OFFSET = 85;



  // The port on which to listen for DNS requests.
  private volatile int listenPort;

  // The port number to use for the first LDAP server in the response.
  private final int serverPort1;

  // The port number to use for the second LDAP server in the response.
  private final int serverPort2;



  /**
   * Creates a new test server instance with the provided information.
   *
   * @param  serverPort1  The port to use for the first server in the response.
   * @param  serverPort2  The port to use for the second server in the response.
   */
  TestDNSSRVRecordServer(final int serverPort1, final int serverPort2)
  {
    this.serverPort1 = serverPort1;
    this.serverPort2 = serverPort2;

    listenPort = -1;
  }



  /**
   * Retrieves the port on which this server is listening for requests.  The
   * server must have been started before this is called.
   *
   * @return  The port on which this server is listening for requests.
   */
  int getListenPort()
  {
    final long stopWaitingTime = System.currentTimeMillis() + 10000L;
    while (System.currentTimeMillis() < stopWaitingTime)
    {
      if (listenPort > 0)
      {
        return listenPort;
      }

      Thread.yield();
    }

    return -1;
  }



  /**
   * Listens for a single request and returns an appropriate response to it.
   */
  @Override()
  public void run()
  {
    try
    {
      // Create a datagram socket that will be used to receive a DNS request.
      final DatagramSocket socket = new DatagramSocket();
      listenPort = socket.getLocalPort();


      // Wait for a request packet to arrive.
      final byte[] requestBuffer = new byte[65536];
      final DatagramPacket requestPacket = new DatagramPacket(requestBuffer,
           requestBuffer.length);
      socket.receive(requestPacket);


      // Create a response packet with the appropriate transaction ID and server
      // ports.
      final byte[] responseBytes = new byte[DEFAULT_RESPONSE_BYTES.length];
      System.arraycopy(DEFAULT_RESPONSE_BYTES, 0, responseBytes, 0,
           responseBytes.length);
      System.arraycopy(requestPacket.getData(), TXN_ID_OFFSET, responseBytes,
           TXN_ID_OFFSET, 2);

      responseBytes[SERVER_1_PORT_OFFSET] =
           (byte) ((serverPort1 & 0xFF00) >> 8);
      responseBytes[SERVER_1_PORT_OFFSET + 1] = (byte) (serverPort1 & 0x00FF);

      responseBytes[SERVER_2_PORT_OFFSET] =
           (byte) ((serverPort2 & 0xFF00) >> 8);
      responseBytes[SERVER_2_PORT_OFFSET + 1] = (byte) (serverPort2 & 0x00FF);

      final DatagramPacket responsePacket = new DatagramPacket(responseBytes,
           responseBytes.length, requestPacket.getSocketAddress());


      // Send the response packet and close the socket.
      socket.send(responsePacket);
      socket.close();
    }
    catch (final Exception e)
    {
      e.printStackTrace();
    }
  }
}
