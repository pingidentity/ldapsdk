/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.logging.Level;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.sasl.SaslClient;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class is used to hold references to the elements involved in network
 * communication for an LDAP connection.
 */
@InternalUseOnly()
final class LDAPConnectionInternals
{
  /**
   * A count of the number of active connections.
   */
  @NotNull private static final AtomicLong ACTIVE_CONNECTION_COUNT =
       new AtomicLong(0L);



  /**
   * A set of thread-local ASN.1 buffers used to prepare messages to be written.
   */
  @NotNull private static final AtomicReference<ThreadLocal<ASN1Buffer>>
       ASN1_BUFFERS = new AtomicReference<>(new ThreadLocal<ASN1Buffer>());



  // The counter that will be used to obtain the next message ID to use when
  // sending requests to the server.
  @NotNull private final AtomicInteger nextMessageID;

  // Indicates whether to operate in synchronous mode.
  private final boolean synchronousMode;

  // The inet address to which the connection is established.
  @NotNull private final InetAddress inetAddress;

  // The port of the server to which the connection is established.
  private final int port;

  // The time that this connection was established.
  private final long connectTime;

  // The LDAP connection with which this connection internals is associated.
  @NotNull private final LDAPConnection connection;

  // The LDAP connection reader with which this connection internals is
  // associated.
  @Nullable private final LDAPConnectionReader connectionReader;

  // The output stream used to send requests to the server.
  @Nullable private volatile OutputStream outputStream;

  // The SASL client used to provide communication security via QoP.
  @Nullable private volatile SaslClient saslClient;

  // The socket used to communicate with the directory server.
  @Nullable private volatile Socket socket;

  // The address of the server to which the connection is established.
  @NotNull private final String host;

  // The write timeout handler for this connection.
  @NotNull private final WriteTimeoutHandler writeTimeoutHandler;



  /**
   * Creates a new instance of this object.
   *
   * @param  connection     The LDAP connection created with this connection
   *                        internals object.
   * @param  options        The set of options for the connection.
   * @param  socketFactory  The socket factory to use to create the socket.
   * @param  host           The address of the server to which the connection
   *                        should be established.
   * @param  inetAddress    The inet address to which the connection is
   *                        established.
   * @param  port           The port of the server to which the connection
   *                        should be established.
   * @param  timeout        The maximum length of time in milliseconds to wait
   *                        for the connection to be established before failing,
   *                        or zero to indicate that no timeout should be
   *                        enforced (although if the attempt stalls long
   *                        enough, then the underlying operating system may
   *                        cause it to timeout).
   *
   * @throws  IOException  If a problem occurs while establishing the
   *                       connection.
   */
  LDAPConnectionInternals(@NotNull final LDAPConnection connection,
                          @NotNull final LDAPConnectionOptions options,
                          @NotNull final SocketFactory socketFactory,
                          @NotNull final String host,
                          @NotNull final InetAddress inetAddress,
                          final int port, final int timeout)
       throws IOException

  {
    this.connection  = connection;
    this.host        = host;
    this.inetAddress = inetAddress;
    this.port        = port;

    if (options.captureConnectStackTrace())
    {
      connection.setConnectStackTrace(Thread.currentThread().getStackTrace());
    }

    connectTime     = System.currentTimeMillis();
    nextMessageID   = new AtomicInteger(0);
    synchronousMode = options.useSynchronousMode();
    saslClient      = null;
    socket          = null;

    writeTimeoutHandler = new WriteTimeoutHandler(connection);

    try
    {
      final ConnectThread connectThread =
           new ConnectThread(socketFactory, inetAddress, port, timeout);
      connectThread.start();
      socket = connectThread.getConnectedSocket();

      if (socket instanceof SSLSocket)
      {
        final SSLSocket sslSocket = (SSLSocket) socket;
        options.getSSLSocketVerifier().verifySSLSocket(host, port, sslSocket);
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      if (socket != null)
      {
        socket.close();
      }

      writeTimeoutHandler.destroy();

      throw new IOException(le);
    }

    try
    {
      Debug.debugConnect(host, port, connection);

      final LDAPConnectionLogger logger = options.getConnectionLogger();
      if (logger != null)
      {
        logger.logConnect(connection, host, inetAddress, port);
      }

      if (options.getReceiveBufferSize() > 0)
      {
        socket.setReceiveBufferSize(options.getReceiveBufferSize());
      }

      if (options.getSendBufferSize() > 0)
      {
        socket.setSendBufferSize(options.getSendBufferSize());
      }

      socket.setKeepAlive(options.useKeepAlive());
      socket.setReuseAddress(options.useReuseAddress());
      socket.setSoLinger(options.useLinger(),
                         options.getLingerTimeoutSeconds());
      socket.setTcpNoDelay(options.useTCPNoDelay());

      final int soTimeout =
           Math.max(0, (int) options.getResponseTimeoutMillis());
      Debug.debug(Level.INFO, DebugType.CONNECT,
           "Setting the SO_TIMEOUT value for connection " + connection +
                " to " + soTimeout + "ms.");
      socket.setSoTimeout(soTimeout);

      outputStream     = new BufferedOutputStream(socket.getOutputStream());
      connectionReader = new LDAPConnectionReader(connection, this);
    }
    catch (final IOException ioe)
    {
      Debug.debugException(ioe);
      try
      {
        socket.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      writeTimeoutHandler.destroy();

      throw ioe;
    }

    ACTIVE_CONNECTION_COUNT.incrementAndGet();
  }



  /**
   * Starts the connection reader for this connection internals.  This will
   * have no effect if the connection is operating in synchronous mode.
   */
  void startConnectionReader()
  {
    if (! synchronousMode)
    {
      connectionReader.start();
    }
  }



  /**
   * Retrieves the LDAP connection with which this connection internals object
   * is associated.
   *
   * @return  The LDAP connection with which this connection internals object is
   *          associated.
   */
  @NotNull()
  LDAPConnection getConnection()
  {
    return connection;
  }



  /**
   * Retrieves the LDAP connection reader used to read responses from the
   * server.
   *
   * @return  The LDAP connection reader used to read responses from the server,
   *          or {@code null} if the connection is operating in synchronous mode
   *          and is not using a connection reader.
   */
  @Nullable()
  LDAPConnectionReader getConnectionReader()
  {
    return connectionReader;
  }



  /**
   * Retrieves the inet address to which this connection is established.
   *
   * @return  The inet address to which this connection is established.
   */
  @NotNull()
  InetAddress getInetAddress()
  {
    return inetAddress;
  }



  /**
   * Retrieves the address of the server to which this connection is
   * established.
   *
   * @return  The address of the server to which this connection is established.
   */
  @NotNull()
  String getHost()
  {
    return host;
  }



  /**
   * Retrieves the port of the server to which this connection is established.
   *
   * @return  The port of the server to which this connection is established.
   */
  int getPort()
  {
    return port;
  }



  /**
   * Retrieves the socket used to communicate with the directory server.
   *
   * @return  The socket used to communicate with the directory server.
   */
  @Nullable()
  Socket getSocket()
  {
    return socket;
  }



  /**
   * Replaces the socket used to communicate with the directory server.  This
   * should only be called by the {@code LDAPConnectionReader} class when
   * replacing the socket for StartTLS processing.
   *
   * @param  socket  The socket used to communicate with the directory server.
   */
  void setSocket(@NotNull final Socket socket)
  {
    this.socket = socket;
  }



  /**
   * Retrieves the output stream used to send requests to the server.
   *
   * @return  The output stream used to send requests to the server.
   */
  @Nullable()
  OutputStream getOutputStream()
  {
    return outputStream;
  }



  /**
   * Indicates whether the socket is currently connected.
   *
   * @return  {@code true} if the socket is currently connected, or
   *          {@code false} if not.
   */
  boolean isConnected()
  {
    return ((socket != null) && socket.isConnected());
  }



  /**
   * Indicates whether this connection is operating in synchronous mode.
   *
   * @return  {@code true} if this connection is operating in synchronous mode,
   *          or {@code false} if not.
   */
  boolean synchronousMode()
  {
    return synchronousMode;
  }



  /**
   * Converts this clear-text connection to one that encrypts all communication
   * using Transport Layer Security.  This method is intended for use as a
   * helper for processing in the course of the StartTLS extended operation and
   * should not be used for other purposes.
   *
   * @param  sslSocketFactory  The SSL socket factory to use to convert an
   *                           insecure connection into a secure connection.  It
   *                           must not be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while converting this
   *                         connection to use TLS.
   */
  void convertToTLS(@NotNull final SSLSocketFactory sslSocketFactory)
       throws LDAPException
  {
    outputStream = connectionReader.doStartTLS(sslSocketFactory);
  }



  /**
   * Converts this clear-text connection to one that uses SASL integrity and/or
   * confidentiality.
   *
   * @param  saslClient  The SASL client that will be used to secure the
   *                     communication.
   *
   * @throws  LDAPException  If a problem occurs while attempting to convert the
   *                         connection to use a SASL security layer.
   */
  void applySASLQoP(@NotNull final SaslClient saslClient)
       throws LDAPException
  {
    this.saslClient = saslClient;
    connectionReader.applySASLQoP(saslClient);
  }



  /**
   * Retrieves the message ID that should be used for the next message to send
   * to the directory server.
   *
   * @return  The message ID that should be used for the next message to send to
   *          the directory server.
   */
  int nextMessageID()
  {
    int msgID = nextMessageID.incrementAndGet();
    if (msgID > 0)
    {
      return msgID;
    }

    while (true)
    {
      if (nextMessageID.compareAndSet(msgID, 1))
      {
        return 1;
      }

      msgID = nextMessageID.incrementAndGet();
      if (msgID > 0)
      {
        return msgID;
      }
    }
  }



  /**
   * Registers the provided response acceptor with the connection reader.
   *
   * @param  messageID         The message ID for which the acceptor is to be
   *                           registered.
   * @param  responseAcceptor  The response acceptor to register.
   *
   * @throws  LDAPException  If another response acceptor is already registered
   *                         with the provided message ID.
   */
  void registerResponseAcceptor(final int messageID,
            @NotNull final ResponseAcceptor responseAcceptor)
       throws LDAPException
  {
    if (! isConnected())
    {
      final LDAPConnectionOptions connectionOptions =
           connection.getConnectionOptions();
      @SuppressWarnings("deprecation")
      final boolean autoReconnect = connectionOptions.autoReconnect();
      final boolean closeRequested = connection.closeRequested();
      if (autoReconnect && (! closeRequested))
      {
        connection.reconnect();
        connection.registerResponseAcceptor(messageID,  responseAcceptor);
      }
      else
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
                                ERR_CONN_NOT_ESTABLISHED.get());
      }
    }

    connectionReader.registerResponseAcceptor(messageID, responseAcceptor);
  }



  /**
   * Deregisters the response acceptor associated with the provided message ID.
   *
   * @param  messageID  The message ID for which to deregister the associated
   *                    response acceptor.
   */
  void deregisterResponseAcceptor(final int messageID)
  {
    connectionReader.deregisterResponseAcceptor(messageID);
  }



  /**
   * Sends the provided LDAP message to the directory server.
   *
   * @param  message            The LDAP message to be sent.
   * @param  sendTimeoutMillis  The maximum length of time, in milliseconds, to
   *                            block while trying to send the request.  If this
   *                            is less than or equal to zero, then no send
   *                            timeout will be enforced.
   * @param  allowRetry         Indicates whether to allow retrying the send
   *                            after a reconnect.
   *
   * @throws  LDAPException  If a problem occurs while sending the message.
   */
  void sendMessage(@NotNull final LDAPMessage message,
                   final long sendTimeoutMillis, final boolean allowRetry)
       throws LDAPException
  {
    if (! isConnected())
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
                              ERR_CONN_NOT_ESTABLISHED.get());
    }

    ASN1Buffer buffer = ASN1_BUFFERS.get().get();
    if (buffer == null)
    {
      buffer = new ASN1Buffer();
      ASN1_BUFFERS.get().set(buffer);
    }

    buffer.clear();
    try
    {
      message.writeTo(buffer);
    }
    catch (final LDAPRuntimeException lre)
    {
      Debug.debugException(lre);
      lre.throwLDAPException();
    }


    try
    {
      final int soTimeout = Math.max(0, (int) sendTimeoutMillis);
      if (Debug.debugEnabled())
      {
        Debug.debug(Level.INFO, DebugType.CONNECT,
             "Setting the SO_TIMEOUT value for connection " + connection +
                  " to " + soTimeout + "ms.");
      }
      socket.setSoTimeout(soTimeout);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    final Long writeID;
    if (sendTimeoutMillis > 0)
    {
      writeID = writeTimeoutHandler.beginWrite(sendTimeoutMillis);
    }
    else
    {
      writeID = null;
    }

    try
    {
      final OutputStream os = outputStream;
      if (os == null)
      {
        // If the message was an unbind request, then we don't care that it
        // didn't get sent.  Otherwise, fail the send attempt but try to
        // reconnect first if appropriate.
        if (message.getProtocolOpType() ==
             LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST)
        {
          return;
        }

        final boolean closeRequested = connection.closeRequested();
        if (allowRetry && (! closeRequested) &&
             (! connection.synchronousMode()))
        {
          connection.reconnect();

          try
          {
            sendMessage(message, sendTimeoutMillis, false);
            return;
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }

        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_CONN_SEND_ERROR_NOT_ESTABLISHED.get(host, port));
      }

      if (saslClient == null)
      {
        buffer.writeTo(os);
      }
      else
      {
        // We need to wrap the data that was read using the SASL client, but we
        // also need to precede that wrapped data with four bytes that specify
        // the number of bytes of wrapped data.
        final byte[] clearBytes = buffer.toByteArray();
        final byte[] saslBytes =
             saslClient.wrap(clearBytes, 0, clearBytes.length);
        final byte[] lengthBytes = new byte[4];
        lengthBytes[0] = (byte) ((saslBytes.length >> 24) & 0xFF);
        lengthBytes[1] = (byte) ((saslBytes.length >> 16) & 0xFF);
        lengthBytes[2] = (byte) ((saslBytes.length >> 8) & 0xFF);
        lengthBytes[3] = (byte) (saslBytes.length & 0xFF);
        os.write(lengthBytes);
        os.write(saslBytes);
      }
      os.flush();
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final IOException ioe)
    {
      Debug.debugException(ioe);

      // If the message was an unbind request, then we don't care that it
      // didn't get sent.  Otherwise, fail the send attempt but try to reconnect
      // first if appropriate.
      if (message.getProtocolOpType() ==
          LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST)
      {
        return;
      }

      final boolean closeRequested = connection.closeRequested();
      if (allowRetry && (! closeRequested) && (! connection.synchronousMode()))
      {
        connection.reconnect();

        try
        {
          sendMessage(message, sendTimeoutMillis, false);
          return;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }

      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_CONN_SEND_ERROR.get(host + ':' + port,
                StaticUtils.getExceptionMessage(ioe)),
           ioe);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_CONN_ENCODE_ERROR.get(host + ':' + port,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
    finally
    {
      if (writeID != null)
      {
        writeTimeoutHandler.writeCompleted(writeID);
      }

      if (buffer.zeroBufferOnClear())
      {
        buffer.clear();
      }
    }
  }



  /**
   * Closes the connection associated with this connection internals.
   */
  void close()
  {
    DisconnectInfo disconnectInfo = connection.getDisconnectInfo();
    if (disconnectInfo == null)
    {
      disconnectInfo = connection.setDisconnectInfo(
           new DisconnectInfo(connection, DisconnectType.UNKNOWN, null, null));
    }

    // Determine if this connection was closed by a finalizer.
    final boolean closedByFinalizer =
         ((disconnectInfo.getType() == DisconnectType.CLOSED_BY_FINALIZER) &&
              (socket != null) && socket.isConnected());

    writeTimeoutHandler.destroy();

    final boolean alreadyClosed;
    if (socket == null)
    {
      alreadyClosed = true;
    }
    else
    {
      alreadyClosed = false;

      try
      {
        try
        {
          outputStream.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }

        try
        {
          socket.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
      finally
      {
        outputStream = null;
        socket = null;
      }

      // Make sure that the connection reader is no longer running.
      try
      {
        connectionReader.close(false);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    if (saslClient != null)
    {
      try
      {
        saslClient.dispose();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
      finally
      {
        saslClient = null;
      }
    }

    if (! alreadyClosed)
    {
      Debug.debugDisconnect(host, port, connection, disconnectInfo.getType(),
           disconnectInfo.getMessage(), disconnectInfo.getCause());

      final LDAPConnectionLogger logger =
           connection.getConnectionOptions().getConnectionLogger();
      if (logger != null)
      {
        logger.logDisconnect(connection, host, port, disconnectInfo.getType(),
             disconnectInfo.getMessage(), disconnectInfo.getCause());
      }
    }

    if (closedByFinalizer && Debug.debugEnabled(DebugType.LDAP))
    {
      Debug.debug(Level.WARNING, DebugType.LDAP,
           "Connection closed by LDAP SDK finalizer:  " + toString());
    }
    disconnectInfo.notifyDisconnectHandler();
    connection.setServerSet(null);

    final long remainingActiveConnections =
         ACTIVE_CONNECTION_COUNT.decrementAndGet();
    if (remainingActiveConnections <= 0L)
    {
      ASN1_BUFFERS.set(new ThreadLocal<ASN1Buffer>());

      if (remainingActiveConnections < 0L)
      {
        // This should never happen, but if it does then we'll reset the count
        // to zero so that we don't keep needlessly resetting the buffers.
        ACTIVE_CONNECTION_COUNT.compareAndSet(remainingActiveConnections, 0L);
      }
    }
  }



  /**
   * Retrieves the time that the connection was established.
   *
   * @return  The time that the connection was established, or -1 if the
   *          connection is not established.
   */
  public long getConnectTime()
  {
    if (isConnected())
    {
      return connectTime;
    }
    else
    {
      return -1L;
    }
  }



  /**
   * Retrieves the number of active connections.
   *
   * @return  The number of active connections.
   */
  static long getActiveConnectionCount()
  {
    return ACTIVE_CONNECTION_COUNT.get();
  }



  /**
   * Retrieves a string representation of this connection internals object.
   *
   * @return  A string representation of this connection internals object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this connection internals object to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPConnectionInternals(host='");
    buffer.append(host);
    buffer.append("', port=");
    buffer.append(port);
    buffer.append(", connected=");
    buffer.append((socket != null) && socket.isConnected());
    buffer.append(", nextMessageID=");
    buffer.append(nextMessageID.get());
    buffer.append(')');
  }
}
