/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
import com.unboundid.util.DebugType;
import com.unboundid.util.InternalUseOnly;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



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
  private static final AtomicLong ACTIVE_CONNECTION_COUNT = new AtomicLong(0L);



  /**
   * A set of thread-local ASN.1 buffers used to prepare messages to be written.
   */
  private static final AtomicReference<ThreadLocal<ASN1Buffer>> ASN1_BUFFERS =
       new AtomicReference<ThreadLocal<ASN1Buffer>>(
            new ThreadLocal<ASN1Buffer>());



  // The counter that will be used to obtain the next message ID to use when
  // sending requests to the server.
  private final AtomicInteger nextMessageID;

  // Indicates whether to operate in synchronous mode.
  private final boolean synchronousMode;

  // The inet address to which the connection is established.
  private final InetAddress inetAddress;

  // The port of the server to which the connection is established.
  private final int port;

  // The time that this connection was established.
  private final long connectTime;

  // The LDAP connection with which this connection internals is associated.
  private final LDAPConnection connection;

  // The LDAP connection reader with which this connection internals is
  // associated.
  private final LDAPConnectionReader connectionReader;

  // The output stream used to send requests to the server.
  private volatile OutputStream outputStream;

  // The SASL client used to provide communication security via QoP.
  private volatile SaslClient saslClient;

  // The socket used to communicate with the directory server.
  private volatile Socket socket;

  // The address of the server to which the connection is established.
  private final String host;



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
  LDAPConnectionInternals(final LDAPConnection connection,
                          final LDAPConnectionOptions options,
                          final SocketFactory socketFactory, final String host,
                          final InetAddress inetAddress, final int port,
                          final int timeout)
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
      debugException(le);

      if (socket != null)
      {
        socket.close();
      }

      throw new IOException(le);
    }
    try
    {
      debugConnect(host, port, connection);

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
      debug(Level.INFO, DebugType.CONNECT,
           "Setting the SO_TIMEOUT value for connection " + connection +
                " to " + soTimeout + "ms.");
      socket.setSoTimeout(soTimeout);

      outputStream     = new BufferedOutputStream(socket.getOutputStream());
      connectionReader = new LDAPConnectionReader(connection, this);
    }
    catch (final IOException ioe)
    {
      debugException(ioe);
      try
      {
        socket.close();
      }
      catch (final Exception e)
      {
        debugException(e);
      }

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
  LDAPConnectionReader getConnectionReader()
  {
    return connectionReader;
  }



  /**
   * Retrieves the inet address to which this connection is established.
   *
   * @return  The inet address to which this connection is established.
   */
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
  void setSocket(final Socket socket)
  {
    this.socket = socket;
  }



  /**
   * Retrieves the output stream used to send requests to the server.
   *
   * @return  The output stream used to send requests to the server.
   */
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
    return socket.isConnected();
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
  void convertToTLS(final SSLSocketFactory sslSocketFactory)
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
   *                         connection to use SASL QoP.
   */
  void applySASLQoP(final SaslClient saslClient)
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
                                final ResponseAcceptor responseAcceptor)
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
  void sendMessage(final LDAPMessage message, final long sendTimeoutMillis,
                   final boolean allowRetry)
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
      debugException(lre);
      lre.throwLDAPException();
    }


    try
    {
      final int soTimeout = Math.max(0, (int) sendTimeoutMillis);
      if (debugEnabled())
      {
        debug(Level.INFO, DebugType.CONNECT,
             "Setting the SO_TIMEOUT value for connection " + connection +
                  " to " + soTimeout + "ms.");
      }
      socket.setSoTimeout(soTimeout);
    }
    catch (final Exception e)
    {
      debugException(e);
    }


    try
    {
      final OutputStream os = outputStream;
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
    catch (final IOException ioe)
    {
      debugException(ioe);

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
          debugException(e);
        }
      }

      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_CONN_SEND_ERROR.get(host + ':' + port, getExceptionMessage(ioe)),
           ioe);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_CONN_ENCODE_ERROR.get(host + ':' + port, getExceptionMessage(e)),
           e);
    }
    finally
    {
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
          socket.isConnected());


    // Make sure that the connection reader is no longer running.
    try
    {
      connectionReader.close(false);
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    try
    {
      outputStream.close();
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    try
    {
      socket.close();
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    if (saslClient != null)
    {
      try
      {
        saslClient.dispose();
      }
      catch (final Exception e)
      {
        debugException(e);
      }
      finally
      {
        saslClient = null;
      }
    }

    debugDisconnect(host, port, connection, disconnectInfo.getType(),
         disconnectInfo.getMessage(), disconnectInfo.getCause());
    if (closedByFinalizer && debugEnabled(DebugType.LDAP))
    {
      debug(Level.WARNING, DebugType.LDAP,
            "Connection closed by LDAP SDK finalizer:  " + toString());
    }
    disconnectInfo.notifyDisconnectHandler();

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
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPConnectionInternals(host='");
    buffer.append(host);
    buffer.append("', port=");
    buffer.append(port);
    buffer.append(", connected=");
    buffer.append(socket.isConnected());
    buffer.append(", nextMessageID=");
    buffer.append(nextMessageID.get());
    buffer.append(')');
  }
}
