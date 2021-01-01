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
package com.unboundid.ldap.sdk;



import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.protocol.UnbindRequestProtocolOp;

import static org.testng.Assert.*;



/**
 * This class provides a very simple directory server that provides support for
 * the UNBOUNDID-TEST SASL mechanism, including support for SASL QoP.  This
 * is an extremely limited server implementation that only supports one
 * connection at a time, only supports synchronous operations, and only supports
 * the following sequence of operations:
 * <OL>
 *   <LI>Connect.</LI>
 *   <LI>UNBOUNDID-TEST bind request with no credentials.</LI>
 *   <LI>UNBOUNDID-TEST bind request with credentials.</LI>
 *   <LI>Search request to retrieve the root DSE.</LI>
 *   <LI>Unbind request.</LI>
 *   <LI>Disconnect.</LI>
 * </OL>
 * The server will run in a background thread.
 */
final class UNBOUNDIDTESTServer
      extends Thread
{
  // Indicates whether a request has been made to stop the server.
  private final AtomicBoolean stopRequested;

  // The port on which to listen for requests.
  private volatile int listenPort;

  // The server socket that will accept client connections.
  private volatile ServerSocket serverSocket;

  // The active client socket, if any.
  private volatile Socket clientSocket;



  /**
   * Creates a new test server with the specified listen port.
   */
  UNBOUNDIDTESTServer()
  {
    stopRequested = new AtomicBoolean(false);
    listenPort    = -1;
    serverSocket  = null;
    clientSocket  = null;
  }



  /**
   * Performs the processing for this server.
   */
  @Override()
  public void run()
  {
    try
    {
      serverSocket = new ServerSocket(0);
      listenPort = serverSocket.getLocalPort();

      while (! stopRequested.get())
      {
        // Accept a connection from a client.
        clientSocket = serverSocket.accept();

        final InputStream  inputStream  = clientSocket.getInputStream();
        final OutputStream outputStream = clientSocket.getOutputStream();
        final ASN1StreamReader asn1Reader =
             new ASN1StreamReader(inputStream, 0);


        // The client must first send an UNBOUNDID-TEST bind request with no
        // credentials.
        LDAPMessage requestMessage = LDAPMessage.readFrom(asn1Reader, false);
        BindRequestProtocolOp bindRequestOp =
             requestMessage.getBindRequestProtocolOp();
        assertEquals(bindRequestOp.getSASLMechanism(), "UNBOUNDID-TEST");
        assertNull(bindRequestOp.getSASLCredentials());


        // Return a "SASL bind in progress" response.
        LDAPMessage responseMessage = new LDAPMessage(
             requestMessage.getMessageID(),
             new BindResponseProtocolOp(
                  ResultCode.SASL_BIND_IN_PROGRESS_INT_VALUE, null, null, null,
                  null));
        outputStream.write(responseMessage.encode().encode());
        outputStream.flush();


        // The next request must be an UNBOUNDID-TEST bind request with
        // credentials.  We won't do anything to validate the credentials, but
        // we will look at the third element to see what QoP the client
        // requested.
        requestMessage = LDAPMessage.readFrom(asn1Reader, false);
        bindRequestOp = requestMessage.getBindRequestProtocolOp();
        assertEquals(bindRequestOp.getSASLMechanism(), "UNBOUNDID-TEST");

        assertNotNull(bindRequestOp.getSASLCredentials());
        final ASN1Sequence credSequence = ASN1Sequence.decodeAsSequence(
             bindRequestOp.getSASLCredentials().getValue());
        final ASN1Element[] credElements = credSequence.elements();
        final SASLQualityOfProtection qop = SASLQualityOfProtection.forName(
             ASN1OctetString.decodeAsOctetString(credElements[2]).
                  stringValue());
        assertNotNull(qop);
        final boolean qopEncode = ((qop == SASLQualityOfProtection.AUTH_INT) ||
             (qop == SASLQualityOfProtection.AUTH_CONF));


        // Return a "success" response.  Include server SASL credentials with
        // the requested QoP.
        responseMessage = new LDAPMessage(requestMessage.getMessageID(),
             new BindResponseProtocolOp(
                  ResultCode.SUCCESS_INT_VALUE, null, null, null,
                  new ASN1OctetString(qop.toString())));
        outputStream.write(responseMessage.encode().encode());
        outputStream.flush();


        // The next request must be a search request to retrieve the root DSE.
        // If the QoP is auth-int or auth-conf, then it will be preceded by
        // four bytes to specify the number of encoded bytes.  But since the
        // encoded representation of an UNBOUNDID-TEST message is the same as
        // regular LDAP (except for the first four bytes), then we don't need
        // do do anything but just read those for bytes before getting the next
        // request.
        if (qopEncode)
        {
          for (int i=0; i < 4; i++)
          {
            inputStream.read();
          }
        }

        requestMessage = LDAPMessage.readFrom(asn1Reader, false);
        final SearchRequestProtocolOp searchRequestOp =
             requestMessage.getSearchRequestProtocolOp();
        assertEquals(searchRequestOp.getBaseDN(), "");
        assertEquals(searchRequestOp.getScope(), SearchScope.BASE);
        assertEquals(searchRequestOp.getFilter(),
             Filter.createPresenceFilter("objectClass"));
        assertEquals(searchRequestOp.getAttributes(), Arrays.asList("1.1"));


        // Return a search result entry message with a DN but no attributes.
        responseMessage = new LDAPMessage(requestMessage.getMessageID(),
             new SearchResultEntryProtocolOp("",
                  Collections.<Attribute>emptyList()));
        byte[] messageBytes = responseMessage.encode().encode();
        if (qopEncode)
        {
          // Since we know it's a tiny response, we know the length will be
          // less than 127 bytes, so we can cheat.
          outputStream.write(0);
          outputStream.write(0);
          outputStream.write(0);
          outputStream.write(messageBytes.length);
        }
        outputStream.write(messageBytes);
        outputStream.flush();


        // Return a "success" search result done message.
        responseMessage = new LDAPMessage(requestMessage.getMessageID(),
             new SearchResultDoneProtocolOp(ResultCode.SUCCESS_INT_VALUE, null,
                  null, null));
        messageBytes = responseMessage.encode().encode();
        if (qopEncode)
        {
          // Since we know it's a tiny response, we know the length will be
          // less than 127 bytes, so we can cheat.
          outputStream.write(0);
          outputStream.write(0);
          outputStream.write(0);
          outputStream.write(messageBytes.length);
        }
        outputStream.write(messageBytes);
        outputStream.flush();


        // The next request should be an unbind request.
        if (qopEncode)
        {
          for (int i=0; i < 4; i++)
          {
            inputStream.read();
          }
        }

        requestMessage = LDAPMessage.readFrom(asn1Reader, false);
        final UnbindRequestProtocolOp unbindRequestOp =
             requestMessage.getUnbindRequestProtocolOp();


        // Close the connection.
        try
        {
          asn1Reader.close();
        } catch (final Exception e) {}

        try
        {
          outputStream.close();
        } catch (final Exception e) {}

        try
        {
          clientSocket.close();
        } catch (final Exception e) {}

        clientSocket = null;
      }
    }
    catch (final Exception e)
    {
      stopServer();
    }
  }



  /**
   * Retrieves the port on which the server is listening.
   *
   * @return  The port on which the server is listening, or -1 if it has not yet
   *          started listening.
   */
  int getListenPort()
  {
    return listenPort;
  }



  /**
   * Shuts down the server.
   */
  void stopServer()
  {
    stopRequested.set(true);

    if (clientSocket != null)
    {
      try
      {
        clientSocket.close();
      } catch (final Exception e) {}
    }

    if (serverSocket != null)
    {
      try
      {
        serverSocket.close();
      } catch (final Exception e) {}
    }
  }
}
