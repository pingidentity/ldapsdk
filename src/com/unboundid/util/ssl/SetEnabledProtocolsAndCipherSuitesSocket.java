/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.util.Set;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an SSL socket implementation that is only intended for
 * use in conjunction with the
 * {@link SetEnabledProtocolsAndCipherSuitesSSLSocketFactory}.  It delegates all
 * operations to a provided socket, except that it will automatically apply a
 * set of enabled protocols and cipher suites when one of the {@code connect}
 * methods is called.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class SetEnabledProtocolsAndCipherSuitesSocket
      extends SSLSocket
{
  // The cipher suites to be enabled when this socket is connected.
  @NotNull private final Set<String> cipherSuites;

  // The protocols to be enabled when this socket is connected.
  @NotNull private final Set<String> protocols;

  // The socket to which most real processing will be delegated.
  @NotNull private final SSLSocket delegateSocket;



  /**
   * Creates a new instance of this socket with the provided information.
   *
   * @param  delegateSocket  The socket to which most processing will be
   *                         delegated.  It must be an {@code SSLSocket} and it
   *                         must not be connected.
   * @param  protocols       The protocols to be enabled when this socket is
   *                         connected.
   * @param  cipherSuites    The cipher suites to be enabled when this socket is
   *                         connected.
   */
  SetEnabledProtocolsAndCipherSuitesSocket(@NotNull final Socket delegateSocket,
       @NotNull final Set<String> protocols,
       @NotNull final Set<String> cipherSuites)
  {
    super();

    Validator.ensureTrue(delegateSocket instanceof SSLSocket);
    Validator.ensureFalse(delegateSocket.isConnected());

    this.delegateSocket = (SSLSocket) delegateSocket;
    this.protocols = protocols;
    this.cipherSuites = cipherSuites;
  }



  /**
   * Connects this socket to the specified endpoint and applies the appropriate
   * set of enabled protocols.
   *
   * @param  endpoint  The endpoint to which the socket should be connected.
   *
   * @throws  IOException  If a problem is encountered while connecting the
   *                       socket.
   */
  @Override()
  public void connect(@NotNull final SocketAddress endpoint)
         throws IOException
  {
    connect(endpoint, 0);
  }



  /**
   * Connects this socket to the specified endpoint and applies the appropriate
   * set of enabled protocols.
   *
   * @param  endpoint  The endpoint to which the socket should be connected.
   * @param  timeout   The maximum length of time to block while attempting to
   *                   establish the connection, in milliseconds.
   *
   * @throws  IOException  If a problem is encountered while connecting the
   *                       socket.
   */
  @Override()
  public void connect(@NotNull final SocketAddress endpoint, final int timeout)
         throws IOException
  {
    delegateSocket.connect(endpoint, timeout);
    SSLUtil.applyEnabledSSLProtocols(delegateSocket, protocols);
    SSLUtil.applyEnabledSSLCipherSuites(delegateSocket, cipherSuites);
  }



  /**
   * Binds this socket to the specified local address.
   *
   * @param  bindpoint  The local address to which the socket should be bound.
   *
   * @throws  IOException  If a problem is encountered while binding the socket.
   */
  @Override()
  public void bind(@NotNull final SocketAddress bindpoint)
         throws IOException
  {
    delegateSocket.bind(bindpoint);
  }



  /**
   * Retrieves the remote address to which the socket is connected.
   *
   * @return  The remote address to which the socket is connected, or
   *          {@code null} if it is not connected.
   */
  @Override()
  @Nullable()
  public InetAddress getInetAddress()
  {
    return delegateSocket.getInetAddress();
  }



  /**
   * Retrieves the local address to which the socket is bound.
   *
   * @return  The local address to which the socket is bound, or {@code null} if
   *          it is not bound.
   */
  @Override()
  @Nullable()
  public InetAddress getLocalAddress()
  {
    return delegateSocket.getLocalAddress();
  }



  /**
   * Retrieves the remote port to which the socket is connected.
   *
   * @return  The remote port to which the socket is connected, or 0 if it is
   *          not connected.
   */
  @Override()
  public int getPort()
  {
    return delegateSocket.getPort();
  }



  /**
   * Retrieves the local port to which the socket is bound.
   *
   * @return  The local port to which the socket is bound, or 0 if it is not
   *          bound.
   */
  @Override()
  public int getLocalPort()
  {
    return delegateSocket.getLocalPort();
  }



  /**
   * Retrieves the address of the remote endpoint to which this socket is
   * connected.
   *
   * @return  The address of the remote endpoint to which this socket is
   *          connected, or {@code null} if it is not connected.
   */
  @Override()
  @Nullable()
  public SocketAddress getRemoteSocketAddress()
  {
    return delegateSocket.getRemoteSocketAddress();
  }



  /**
   * Retrieves the address of the local bindpoint to which this socket is bound.
   *
   * @return  The address of the local bindpoint to which this socket is bound,
   *          or {@code null} if it is not bound.
   */
  @Override()
  @Nullable()
  public SocketAddress getLocalSocketAddress()
  {
    return delegateSocket.getLocalSocketAddress();
  }



  /**
   * Retrieves the socket channel associated with this socket.
   *
   * @return  The socket channel associated with this socket, or {@code null} if
   *          there is no socket channel.
   */
  @Override()
  @Nullable()
  public SocketChannel getChannel()
  {
    return delegateSocket.getChannel();
  }



  /**
   * Retrieves the input stream that may be used to read data from this socket.
   *
   * @return  The input stream that may be used to read data from this socket.
   *
   * @throws  IOException  If a problem is encountered while getting the input
   *                       stream.
   */
  @Override()
  @NotNull()
  public InputStream getInputStream()
         throws IOException
  {
    return delegateSocket.getInputStream();
  }



  /**
   * Retrieves the output stream that may be used to send data over this socket.
   *
   * @return  The output stream that may be used to send data over this socket.
   *
   * @throws  IOException  If a problem is encountered while getting the output
   *                       stream.
   */
  @Override()
  @NotNull()
  public OutputStream getOutputStream()
         throws IOException
  {
    return delegateSocket.getOutputStream();
  }



  /**
   * Specifies whether to enable TCP_NODELAY for this socket.
   *
   * @param  on  Indicates whether to enable TCP_NODELAY for this socket.
   *
   * @throws  SocketException  If a problem is encountered while applying this
   *                           setting.
   */
  @Override()
  public void setTcpNoDelay(final boolean on)
         throws SocketException
  {
    delegateSocket.setTcpNoDelay(on);
  }



  /**
   * Indicates whether TCP_NODELAY is enabled for this socket.
   *
   * @return  {@code true} if TCP_NODELAY is enabled for this socket, or
   *          {@code false} if not.
   *
   * @throws  SocketException  If a problem is encountered while making the
   *                           determination.
   */
  @Override()
  public boolean getTcpNoDelay()
         throws SocketException
  {
    return delegateSocket.getTcpNoDelay();
  }



  /**
   * Specifies whether to enable SO_LINGER for this socket.
   *
   * @param  on      Indicates whether to enable SO_LINGER for this socket.
   * @param  linger  The linger timeout, in seconds, if SO_LINGER should be
   *                 enabled.
   *
   * @throws  SocketException  If a problem is encountered while applying this
   *                           setting.
   */
  @Override()
  public void setSoLinger(final boolean on, final int linger)
         throws SocketException
  {
    delegateSocket.setSoLinger(on, linger);
  }



  /**
   * Retrieves the linger timeout for this socket.
   *
   * @return  The linger timeout for this socket, or -1 if SO_LINGER is not
   *          enabled.
   *
   * @throws  SocketException  If a problem is encountered while making the
   *                           determination.
   */
  @Override()
  public int getSoLinger()
         throws SocketException
  {
    return delegateSocket.getSoLinger();
  }



  /**
   * Sends one byte of urgent data on this socket.
   *
   * @param  data  The byte to send.
   *
   * @throws  IOException  If a problem is encountered while sending the data.
   */
  @Override()
  public void sendUrgentData(final int data)
         throws IOException
  {
    // This is not supported for SSL sockets.  Although we could delegate the
    // call to the underlying socket, throwing an exception here will provide
    // for better test coverage.
    throw new SocketException(
         ERR_SET_ENABLED_PROTOCOLS_SOCKET_URGENT_DATA_NOT_SUPPORTED.get());
  }



  /**
   * Specifies whether to use OOBINLINE for this socket.
   *
   * @param  on  Indicates whether to use OOBINLINE for this socket.
   *
   * @throws  SocketException  If a problem is encountered while setting the
   *                           option.
   */
  @Override()
  public void setOOBInline(final boolean on)
         throws SocketException
  {
    // This is not supported for SSL sockets.  Although we could delegate the
    // call to the underlying socket, throwing an exception here will provide
    // for better test coverage.
    throw new SocketException(
         ERR_SET_ENABLED_PROTOCOLS_SOCKET_URGENT_DATA_NOT_SUPPORTED.get());
  }



  /**
   * Indicates whether to use OOBINLINE for this socket.
   *
   * @return  {@code true} if OOBINLINE is enabled for this socket, or
   *          {@code false} if not.
   *
   * @throws  SocketException  If a problem is encountered while making the
   *                           determination.
   */
  @Override()
  public boolean getOOBInline()
         throws SocketException
  {
    // This is not supported for SSL sockets.  Although we could delegate the
    // call to the underlying socket, throwing an exception here will provide
    // for better test coverage.
    throw new SocketException(
         ERR_SET_ENABLED_PROTOCOLS_SOCKET_URGENT_DATA_NOT_SUPPORTED.get());
  }



  /**
   * Sets the SO_TIMEOUT value for this socket.
   *
   * @param  timeout  The SO_TIMEOUT value, in milliseconds.
   *
   * @throws  SocketException  If a problem is encountered while applying the
   *                           setting.
   */
  @Override()
  public void setSoTimeout(final int timeout)
         throws SocketException
  {
    delegateSocket.setSoTimeout(timeout);
  }



  /**
   * Retrieves the SO_TIMEOUT value for this socket, in milliseconds.
   *
   * @return  The SO_TIMEOUT value for this socket, in milliseconds.
   *
   * @throws  SocketException  If a problem is encountered while making the
   *                           determination.
   */
  @Override()
  public int getSoTimeout()
         throws SocketException
  {
    return delegateSocket.getSoTimeout();
  }



  /**
   * Sets the send buffer size for this socket.
   *
   * @param  size  The send buffer size, in bytes.
   *
   * @throws  SocketException  If a problem is encountered while setting the
   *                           option.
   */
  @Override()
  public void setSendBufferSize(final int size)
         throws SocketException
  {
    delegateSocket.setSendBufferSize(size);
  }



  /**
   * Retrieves the send buffer size for this socket.
   *
   * @return  The send buffer size for this socket.
   *
   * @throws  SocketException  If a problem is encountered while making the
   *                           determination.
   */
  @Override()
  public int getSendBufferSize()
         throws SocketException
  {
    return delegateSocket.getSendBufferSize();
  }



  /**
   * Sets the receive buffer size for this socket.
   *
   * @param  size  The receive buffer size, in bytes.
   *
   * @throws  SocketException  If a problem is encountered while setting the
   *                           option.
   */
  @Override()
  public void setReceiveBufferSize(final int size)
         throws SocketException
  {
    delegateSocket.setReceiveBufferSize(size);
  }



  /**
   * Retrieves the receive buffer size for this socket.
   *
   * @return  The receive buffer size for this socket.
   *
   * @throws  SocketException  If a problem is encountered while making the
   *                           determination.
   */
  @Override()
  public int getReceiveBufferSize()
         throws SocketException
  {
    return delegateSocket.getReceiveBufferSize();
  }



  /**
   * Specifies whether to use SO_KEEPALIVE for this socket.
   *
   * @param  on  Indicates whether to use SO_KEEPALIVE for this socket.
   *
   * @throws  SocketException  If a problem is encountered while setting the
   *                           option.
   */
  @Override()
  public void setKeepAlive(final boolean on)
         throws SocketException
  {
    delegateSocket.setKeepAlive(on);
  }



  /**
   * Indicates whether SO_KEEPALIVE is enabled for this socket.
   *
   * @return  {@code true} if SO_KEEPALIVE is enabled for this socket, or
   *          {@code false} if not.
   *
   * @throws  SocketException  If a problem is encountered while making the
   *                           determination.
   */
  @Override()
  public boolean getKeepAlive()
         throws SocketException
  {
    return delegateSocket.getKeepAlive();
  }



  /**
   * Specifies the traffic class for this socket.
   *
   * @param  tc  The traffic class for this socket.
   *
   * @throws  SocketException  If a problem is encountered while setting the
   *                           option.
   */
  @Override()
  public void setTrafficClass(final int tc)
         throws SocketException
  {
    delegateSocket.setTrafficClass(tc);
  }



  /**
   * Retrieves the traffic class for this socket.
   *
   * @return  The traffic class for this socket.
   *
   * @throws  SocketException  If a problem is encountered while making the
   *                           determination.
   */
  @Override()
  public int getTrafficClass()
         throws SocketException
  {
    return delegateSocket.getTrafficClass();
  }



  /**
   * Specifies whether to use SO_REUSEADDR for this socket.
   *
   * @param  on  Indicates whether to use SO_REUSEADDR for this socket.
   *
   * @throws  SocketException  If a problem is encountered while setting the
   *                           option.
   */
  @Override()
  public void setReuseAddress(final boolean on)
         throws SocketException
  {
    delegateSocket.setReuseAddress(on);
  }



  /**
   * Indicates whether to use SO_REUSEADDR for this socket.
   *
   * @return  {@code true} if SO_REUSEADDR should be used for this socket, or
   *          {@code false} if not.
   *
   * @throws  SocketException  If a problem is encountered while making the
   *                           determination.
   */
  @Override()
  public boolean getReuseAddress()
         throws SocketException
  {
    return delegateSocket.getReuseAddress();
  }



  /**
   * Closes this socket.
   *
   * @throws  IOException  If a problem is encountered while closing the socket.
   */
  @Override()
  public void close()
         throws IOException
  {
    delegateSocket.close();
  }



  /**
   * Shuts down the input stream portion of this socket.
   *
   * @throws  IOException  If a problem is encountered while shutting down the
   *                       input stream.
   */
  @Override()
  public void shutdownInput()
         throws IOException
  {
    // This is not supported for SSL sockets.  Although we could delegate the
    // call to the underlying socket, throwing an exception here will provide
    // for better test coverage.
    throw new UnsupportedOperationException(
         ERR_SET_ENABLED_PROTOCOLS_SOCKET_SHUTDOWN_INPUT.get());
  }



  /**
   * Shuts down the output stream portion of this socket.
   *
   * @throws  IOException  If a problem is encountered while shutting down the
   *                       output stream.
   */
  @Override()
  public void shutdownOutput()
         throws IOException
  {
    // This is not supported for SSL sockets.  Although we could delegate the
    // call to the underlying socket, throwing an exception here will provide
    // for better test coverage.
    throw new UnsupportedOperationException(
         ERR_SET_ENABLED_PROTOCOLS_SOCKET_SHUTDOWN_OUTPUT.get());
  }



  /**
   * Indicates whether this socket is currently connected to a remote address.
   *
   * @return  {@code true} if this socket is connected, or {@code false} if not.
   */
  @Override()
  public boolean isConnected()
  {
    return delegateSocket.isConnected();
  }



  /**
   * Indicates whether this socket is currently bound to a local address.
   *
   * @return  {@code true} if this socket is bound, or {@code false} if not.
   */
  @Override()
  public boolean isBound()
  {
    return delegateSocket.isBound();
  }



  /**
   * Indicates whether this socket is currently closed.
   *
   * @return  {@code true} if this socket is closed, or {@code false} if not.
   */
  @Override()
  public boolean isClosed()
  {
    return delegateSocket.isClosed();
  }



  /**
   * Indicates whether the input portion of this socket has been shut down.
   *
   * @return  {@code true} if the input portion of this socket has been shut
   *          down, or {@code false} if not.
   */
  @Override()
  public boolean isInputShutdown()
  {
    return delegateSocket.isInputShutdown();
  }



  /**
   * Indicates whether the output portion of this socket has been shut down.
   *
   * @return  {@code true} if the output portion of this socket has been shut
   *          down, or {@code false} if not.
   */
  @Override()
  public boolean isOutputShutdown()
  {
    return delegateSocket.isOutputShutdown();
  }



  /**
   * Sets the performance preferences for this socket.
   *
   * @param  connectionTime  A value indicating the relative importance of
   *                         a short connection time.
   * @param  latency         A value expressing the relative importance of low
   *                         latency.
   * @param  bandwidth       A value expressing the relative importance of high
   *                         bandwidth.
   */
  @Override()
  public void setPerformancePreferences(final int connectionTime,
                                        final int latency,
                                        final int bandwidth)
  {
    delegateSocket.setPerformancePreferences(connectionTime, latency,
         bandwidth);
  }



  /**
   * Retrieves the set of supported cipher suites for this socket.
   *
   * @return  The set of supported cipher suites for this socket.
   */
  @Override()
  @NotNull()
  public String[] getSupportedCipherSuites()
  {
    return delegateSocket.getSupportedCipherSuites();
  }



  /**
   * Retrieves the set of enabled cipher suites for this socket.
   *
   * @return  The set of enabled cipher suites for this socket.
   */
  @Override()
  @NotNull()
  public String[] getEnabledCipherSuites()
  {
    return delegateSocket.getEnabledCipherSuites();
  }



  /**
   * Specifies the set of enabled cipher suites for this socket.
   *
   * @param  suites  The set of enabled cipher suites for this socket.
   */
  @Override()
  public void setEnabledCipherSuites(@NotNull final String[] suites)
  {
    delegateSocket.setEnabledCipherSuites(suites);
  }



  /**
   * Retrieves the set of supported protocols for this socket.
   *
   * @return  The set of supported protocols for this socket.
   */
  @Override()
  @NotNull()
  public String[] getSupportedProtocols()
  {
    return delegateSocket.getSupportedProtocols();
  }



  /**
   * Retrieves the set of enabled protocols for this socket.
   *
   * @return  The set of enabled protocols for this socket.
   */
  @Override()
  @NotNull()
  public String[] getEnabledProtocols()
  {
    return delegateSocket.getEnabledProtocols();
  }



  /**
   * Specifies the set of enabled protocols for this socket.
   *
   * @param  protocols  The set of enabled protocols for this socket.
   */
  @Override()
  public void setEnabledProtocols(@NotNull final String[] protocols)
  {
    delegateSocket.setEnabledProtocols(protocols);
  }



  /**
   * Retrieves the SSL session for this socket.
   *
   * @return  The SSL session for this socket.
   */
  @Override()
  @NotNull()
  public SSLSession getSession()
  {
    return delegateSocket.getSession();
  }



  /**
   * Adds the provided handshake completed listener to this socket.
   *
   * @param  listener  The handshake completed listener to add to this socket.
   */
  @Override()
  public void addHandshakeCompletedListener(
                   @NotNull final HandshakeCompletedListener listener)
  {
    delegateSocket.addHandshakeCompletedListener(listener);
  }



  /**
   * Removes the provided handshake completed listener from this socket.
   *
   * @param  listener  The handshake completed listener to remove from this
   *                   socket.
   */
  @Override()
  public void removeHandshakeCompletedListener(
                   @NotNull final HandshakeCompletedListener listener)
  {
    delegateSocket.removeHandshakeCompletedListener(listener);
  }



  /**
   * Initiates an SSL handshake on this connection.
   *
   * @throws  IOException  If a problem occurs while initiating a handshake.
   */
  @Override()
  public void startHandshake()
         throws IOException
  {
    delegateSocket.startHandshake();
  }



  /**
   * Specifies whether to use client mode when handshaking.
   *
   * @param  mode  Indicates whether to use client mode when handshaking.
   */
  @Override()
  public void setUseClientMode(final boolean mode)
  {
    delegateSocket.setUseClientMode(mode);
  }



  /**
   * Indicates whether to use client mode when handshaking.
   *
   * @return  {@code true} if client mode should be used, or {@code false} if
   *          server mode should be used.
   */
  @Override()
  public boolean getUseClientMode()
  {
    return delegateSocket.getUseClientMode();
  }



  /**
   * Specifies whether to require client authentication for this socket.
   *
   * @param  need  Indicates whether to require client authentication for this
   *               socket.
   */
  @Override()
  public void setNeedClientAuth(final boolean need)
  {
    delegateSocket.setNeedClientAuth(need);
  }



  /**
   * Indicates whether to require client authentication for this socket.
   *
   * @return  {@code true} if client authentication is required, or
   *          {@code false} if not.
   */
  @Override()
  public boolean getNeedClientAuth()
  {
    return delegateSocket.getNeedClientAuth();
  }



  /**
   * Specifies whether to request client authentication for this socket.
   *
   * @param  want  Indicates whether to request client authentication for this
   *               socket.
   */
  @Override()
  public void setWantClientAuth(final boolean want)
  {
    delegateSocket.setWantClientAuth(want);
  }



  /**
   * Indicates whether to request client authentication for this socket.
   *
   * @return  {@code true} if client authentication should be requested, or
   *          {@code false} if not.
   */
  @Override()
  public boolean getWantClientAuth()
  {
    return delegateSocket.getWantClientAuth();
  }



  /**
   * Specifies whether new SSL sessions may be created by this socket.
   *
   * @param  flag  Indicates whether new SSL sessions may be created by this
   *               socket.
   */
  @Override()
  public void setEnableSessionCreation(final boolean flag)
  {
    delegateSocket.setEnableSessionCreation(flag);
  }



  /**
   * Indicates whether new SSL sessions may be created by this socket.
   *
   * @return  {@code true} if new SSL sessions may be created by this socket,
   *          or {@code false} if not.
   */
  @Override()
  public boolean getEnableSessionCreation()
  {
    return delegateSocket.getEnableSessionCreation();
  }



  /**
   * Retrieves a string representation of this socket.
   *
   * @return  A string representation of this socket.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return delegateSocket.toString();
  }
}
