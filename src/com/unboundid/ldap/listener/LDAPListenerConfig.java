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
package com.unboundid.ldap.listener;



import java.net.InetAddress;
import javax.net.ServerSocketFactory;

import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a mechanism for defining the configuration to use for an
 * {@link LDAPListener} instance.  Note that while instances of this class are
 * not inherently threadsafe, a private copy of the configuration will be
 * created whenever a new {@code LDAPListener} is created so that this
 * configuration may continue to be altered for new instances without impacting
 * any existing listeners.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPListenerConfig
{
  /**
   * The default maximum message size that will be used if no other value is
   * specified.
   */
  static final int DEFAULT_MAX_MESSAGE_SIZE_BYTES =
       new LDAPConnectionOptions().getMaxMessageSize();



  // Indicates whether the listener should request that the client provide a
  // certificate.
  private boolean requestClientCertificate;

  // Indicates whether the listener should require that the client provide a
  // certificate.
  private boolean requireClientCertificate;

  // Indicates whether to use the SO_KEEPALIVE socket option for sockets
  // accepted by the listener.
  private boolean useKeepAlive;

  // Indicates whether to use the SO_LINGER socket option for sockets accepted
  // by the listener.
  private boolean useLinger;

  // Indicates whether to use the SO_REUSEADDR socket option for sockets
  // accepted by the listener.
  private boolean useReuseAddress;

  // Indicates whether to use the TCP_NODELAY for sockets accepted by the
  // listener.
  private boolean useTCPNoDelay;

  // The address on which to listen for client connections.
  @Nullable private InetAddress listenAddress;

  // The linger timeout in seconds to use for sockets accepted by the listener.
  private int lingerTimeout;

  // The port on which to listen for client connections.
  private int listenPort;

  // The maximum number of concurrent connections that will be allowed.
  private int maxConnections;

  // The maximum size in bytes for encoded messages that the listener will
  // accept.
  private int maxMessageSizeBytes;

  // The receive buffer size to use for sockets accepted by the listener.
  private int receiveBufferSize;

  // The send buffer size to use for sockets accepted by the listener.
  private int sendBufferSize;

  // The exception handler to use for the listener and associated connections.
  @Nullable private LDAPListenerExceptionHandler exceptionHandler;

  // The request handler that will be used to process requests read from
  // clients.
  @NotNull private LDAPListenerRequestHandler requestHandler;

  // The factory that will be used to create server sockets.
  @NotNull private ServerSocketFactory serverSocketFactory;



  /**
   * Creates a new listener configuration.
   *
   * @param  listenPort      The port on which to listen for client connections.
   *                         It must be an integer between 1 and 65535, or 0 to
   *                         indicate that a free port should be chosen by the
   *                         JVM.
   * @param  requestHandler  The request handler that will be used to process
   *                         requests read from clients.  It must not be
   *                         {@code null}.
   */
  public LDAPListenerConfig(final int listenPort,
              @NotNull final LDAPListenerRequestHandler requestHandler)
  {
    Validator.ensureTrue((listenPort >= 0) && (listenPort <= 65_535));
    Validator.ensureNotNull(requestHandler);

    this.listenPort     = listenPort;
    this.requestHandler = requestHandler;

    requestClientCertificate = false;
    requireClientCertificate = false;
    useKeepAlive             = true;
    useLinger                = true;
    useReuseAddress          = true;
    useTCPNoDelay            = true;
    lingerTimeout            = 5;
    listenAddress            = null;
    maxConnections           = 0;
    maxMessageSizeBytes      = DEFAULT_MAX_MESSAGE_SIZE_BYTES;
    receiveBufferSize        = 0;
    sendBufferSize           = 0;
    exceptionHandler         = null;
    serverSocketFactory      = ServerSocketFactory.getDefault();
  }



  /**
   * Retrieves the port number on which to listen for client connections.  A
   * value of zero indicates that the listener should allow the JVM to choose a
   * free port.
   *
   * @return  The port number on which to listen for client connections.
   */
  public int getListenPort()
  {
    return listenPort;
  }



  /**
   * Specifies the port number on which to listen for client connections.  The
   * provided value must be between 1 and 65535, or it may be 0 to indicate that
   * the JVM should select a free port on the system.
   *
   * @param  listenPort  The port number on which to listen for client
   *                     connections.
   */
  public void setListenPort(final int listenPort)
  {
    Validator.ensureTrue((listenPort >= 0) && (listenPort <= 65_535));

    this.listenPort = listenPort;
  }



  /**
   * Retrieves the LDAP listener request handler that should be used to process
   * requests read from clients.
   *
   * @return  The LDAP listener request handler that should be used to process
   *          requests read from clients.
   */
  @NotNull()
  public LDAPListenerRequestHandler getRequestHandler()
  {
    return requestHandler;
  }



  /**
   * Specifies the LDAP listener request handler that should be used to process
   * requests read from clients.
   *
   * @param  requestHandler  The LDAP listener request handler that should be
   *                         used to process requests read from clients.  It
   *                         must not be {@code null}.
   */
  public void setRequestHandler(
                   @NotNull final LDAPListenerRequestHandler requestHandler)
  {
    Validator.ensureNotNull(requestHandler);

    this.requestHandler = requestHandler;
  }



  /**
   * Indicates whether to use the SO_KEEPALIVE socket option for sockets
   * accepted by the listener.
   *
   * @return  {@code true} if the SO_KEEPALIVE socket option should be used for
   *          sockets accepted by the listener, or {@code false} if not.
   */
  public boolean useKeepAlive()
  {
    return useKeepAlive;
  }



  /**
   * Specifies whether to use the SO_KEEPALIVE socket option for sockets
   * accepted by the listener.
   *
   * @param  useKeepAlive  Indicates whether to use the SO_KEEPALIVE socket
   *                       option for sockets accepted by the listener.
   */
  public void setUseKeepAlive(final boolean useKeepAlive)
  {
    this.useKeepAlive = useKeepAlive;
  }



  /**
   * Indicates whether to use the SO_LINGER socket option for sockets accepted
   * by the listener.
   *
   * @return  {@code true} if the SO_LINGER socket option should be used for
   *          sockets accepted by the listener, or {@code false} if not.
   */
  public boolean useLinger()
  {
    return useLinger;
  }



  /**
   * Specifies whether to use the SO_LINGER socket option for sockets accepted
   * by the listener.
   *
   * @param  useLinger  Indicates whether to use the SO_LINGER socket option for
   *                    sockets accepted by the listener.
   */
  public void setUseLinger(final boolean useLinger)
  {
    this.useLinger = useLinger;
  }



  /**
   * Indicates whether to use the SO_REUSEADDR socket option for sockets
   * accepted by the listener.
   *
   * @return  {@code true} if the SO_REUSEADDR socket option should be used for
   *          sockets accepted by the listener, or {@code false} if not.
   */
  public boolean useReuseAddress()
  {
    return useReuseAddress;
  }



  /**
   * Specifies whether to use the SO_REUSEADDR socket option for sockets
   * accepted by the listener.
   *
   * @param  useReuseAddress  Indicates whether to use the SO_REUSEADDR socket
   *                          option for sockets accepted by the listener.
   */
  public void setUseReuseAddress(final boolean useReuseAddress)
  {
    this.useReuseAddress = useReuseAddress;
  }



  /**
   * Indicates whether to use the TCP_NODELAY socket option for sockets accepted
   * by the listener.
   *
   * @return  {@code true} if the TCP_NODELAY socket option should be used for
   *          sockets accepted by the listener, or {@code false} if not.
   */
  public boolean useTCPNoDelay()
  {
    return useTCPNoDelay;
  }



  /**
   * Specifies whether to use the TCP_NODELAY socket option for sockets accepted
   * by the listener.
   *
   * @param  useTCPNoDelay  Indicates whether to use the TCP_NODELAY socket
   *                        option for sockets accepted by the listener.
   */
  public void setUseTCPNoDelay(final boolean useTCPNoDelay)
  {
    this.useTCPNoDelay = useTCPNoDelay;
  }



  /**
   * Retrieves the address on which to listen for client connections, if
   * defined.
   *
   * @return  The address on which to listen for client connections, or
   *          {@code null} if it should listen on all available addresses on all
   *          interfaces.
   */
  @Nullable()
  public InetAddress getListenAddress()
  {
    return listenAddress;
  }



  /**
   * Specifies the address on which to listen for client connections.
   *
   * @param  listenAddress  The address on which to listen for client
   *                        connections.  It may be {@code null} to indicate
   *                        that it should listen on all available addresses on
   *                        all interfaces.
   */
  public void setListenAddress(@Nullable final InetAddress listenAddress)
  {
    this.listenAddress = listenAddress;
  }



  /**
   * Retrieves the timeout in seconds that should be used if the SO_LINGER
   * socket option is enabled.
   *
   * @return  The timeout in seconds that should be used if the SO_LINGER socket
   *           option is enabled.
   */
  public int getLingerTimeoutSeconds()
  {
    return lingerTimeout;
  }



  /**
   * Specifies the timeout in seconds that should be used if the SO_LINGER
   * socket option is enabled.
   *
   * @param  lingerTimeout  The timeout in seconds that should be used if the
   *                        SO_LINGER socket option is enabled.  The value must
   *                        be between 0 and 65535, inclusive.
   */
  public void setLingerTimeoutSeconds(final int lingerTimeout)
  {
    Validator.ensureTrue((lingerTimeout >= 0) && (lingerTimeout <= 65_535));

    this.lingerTimeout = lingerTimeout;
  }



  /**
   * Retrieves the maximum number of concurrent connections that the listener
   * will allow.  If a client tries to establish a new connection while the
   * listener already has the maximum number of concurrent connections, then the
   * new connection will be rejected.
   *
   * @return  The maximum number of concurrent connections that the listener
   *          will allow, or zero if no limit should be enforced.
   */
  public int getMaxConnections()
  {
    return maxConnections;
  }



  /**
   * Specifies the maximum number of concurrent connections that the listener
   * will allow.  If a client tries to establish a new connection while the
   * listener already has the maximum number of concurrent connections, then the
   * new connection will be rejected.
   *
   * @param  maxConnections  The maximum number of concurrent connections that
   *                         the listener will allow.  A value that is less than
   *                         or equal to zero indicates no limit.
   */
  public void setMaxConnections(final int maxConnections)
  {
    if (maxConnections > 0)
    {
      this.maxConnections = maxConnections;
    }
    else
    {
      this.maxConnections = 0;
    }
  }



  /**
   * Retrieves the maximum size in bytes for LDAP messages that will be accepted
   * by this listener.
   *
   * @return  The maximum size in bytes for LDAP messages that will be accepted
   *          by this listener.
   */
  public int getMaxMessageSizeBytes()
  {
    return maxMessageSizeBytes;
  }



  /**
   * Specifies the maximum size in bytes for LDAP messages that will be accepted
   * by this listener.
   *
   * @param  maxMessageSizeBytes  The maximum size in bytes for LDAP messages
   *                              that will be accepted by this listener.  A
   *                              value that is less than or equal to zero will
   *                              use the maximum allowed message size.
   */
  public void setMaxMessageSizeBytes(final int maxMessageSizeBytes)
  {
    if (maxMessageSizeBytes > 0)
    {
      this.maxMessageSizeBytes = maxMessageSizeBytes;
    }
    else
    {
      this.maxMessageSizeBytes = Integer.MAX_VALUE;
    }
  }



  /**
   * Retrieves the receive buffer size that should be used for sockets accepted
   * by the listener.
   *
   * @return  The receive buffer size that should be used for sockets accepted
   *          by the listener, or 0 if the default receive buffer size should be
   *          used.
   */
  public int getReceiveBufferSize()
  {
    return receiveBufferSize;
  }



  /**
   * Specifies the receive buffer size that should be used for sockets accepted
   * by the listener.  A value less than or equal to zero indicates that the
   * default receive buffer size should be used.
   *
   * @param  receiveBufferSize  The receive buffer size that should be used for
   *                            sockets accepted by the listener.
   */
  public void setReceiveBufferSize(final int receiveBufferSize)
  {
    if (receiveBufferSize > 0)
    {
      this.receiveBufferSize = receiveBufferSize;
    }
    else
    {
      this.receiveBufferSize = 0;
    }
  }



  /**
   * Retrieves the send  buffer size that should be used for sockets accepted
   * by the listener.
   *
   * @return  The send buffer size that should be used for sockets accepted by
   *          the listener, or 0 if the default send buffer size should be used.
   */
  public int getSendBufferSize()
  {
    return sendBufferSize;
  }



  /**
   * Specifies the send buffer size that should be used for sockets accepted by
   * the listener.  A value less than or equal to zero indicates that the
   * default send buffer size should be used.
   *
   * @param  sendBufferSize  The send buffer size that should be used for
   *                         sockets accepted by the listener.
   */
  public void setSendBufferSize(final int sendBufferSize)
  {
    if (sendBufferSize > 0)
    {
      this.sendBufferSize = sendBufferSize;
    }
    else
    {
      this.sendBufferSize = 0;
    }
  }



  /**
   * Retrieves the exception handler that should be notified of any exceptions
   * caught while attempting to accept or interact with a client connection.
   *
   * @return  The exception handler that should be notified of any exceptions
   *          caught while attempting to accept or interact with a client
   *          connection, or {@code null} if none is defined.
   */
  @Nullable()
  public LDAPListenerExceptionHandler getExceptionHandler()
  {
    return exceptionHandler;
  }



  /**
   * Specifies the exception handler that should be notified of any exceptions
   * caught while attempting to accept or interact with a client connection.
   *
   * @param  exceptionHandler  The exception handler that should be notified of
   *                           any exceptions encountered during processing.  It
   *                           may be {@code null} if no exception handler
   *                           should be used.
   */
  public void setExceptionHandler(
              @Nullable final LDAPListenerExceptionHandler exceptionHandler)
  {
    this.exceptionHandler = exceptionHandler;
  }



  /**
   * Retrieves the factory that will be used to create the server socket that
   * will listen for client connections.
   *
   * @return  The factory that will be used to create the server socket that
   *          will listen for client connections.
   */
  @NotNull()
  public ServerSocketFactory getServerSocketFactory()
  {
    return serverSocketFactory;
  }



  /**
   * Specifies the factory that will be used to create the server socket that
   * will listen for client connections.
   *
   * @param  serverSocketFactory  The factory that will be used to create the
   *                              server socket that will listen for client
   *                              connections.  It may be {@code null} to use
   *                              the JVM-default server socket factory.
   */
  public void setServerSocketFactory(
                   @Nullable final ServerSocketFactory serverSocketFactory)
  {
    if (serverSocketFactory == null)
    {
      this.serverSocketFactory = ServerSocketFactory.getDefault();
    }
    else
    {
      this.serverSocketFactory = serverSocketFactory;
    }
  }



  /**
   * Indicates whether the listener should request that the client present its
   * own certificate chain during TLS negotiation.  This will be ignored for
   * non-TLS-based connections.
   *
   * @return  {@code true} if the listener should request that the client
   *          present its own certificate chain during TLS negotiation, or
   *          {@code false} if not.
   */
  public boolean requestClientCertificate()
  {
    return requestClientCertificate;
  }



  /**
   * Specifies whether the listener should request that the client present its
   * own certificate chain during TLS negotiation.  This will be ignored for
   * non-TLS-based connections.
   *
   * @param  requestClientCertificate  Indicates whether the listener should
   *                                   request that the client present its own
   *                                   certificate chain during TLS negotiation.
   */
  public void setRequestClientCertificate(
                   final boolean requestClientCertificate)
  {
    this.requestClientCertificate = requestClientCertificate;
  }



  /**
   * Indicates whether the listener should require that the client present its
   * own certificate chain during TLS negotiation and should fail negotiation
   * if no certificate chain was provided.  This will be ignored for
   * non-TLS-based connections, and it will also be ignored if
   * {@link #requestClientCertificate} returns false.
   *
   * @return  {@code true} if the listener should require that the client
   *          present its own certificate chain during TLS negotiation, or
   *          {@code false} if TLS negotiation should continue even if the
   *          client did not present a certificate chain when requested.
   */
  public boolean requireClientCertificate()
  {
    return requireClientCertificate;
  }



  /**
   * Specifies whether the listener should require that the client present its
   * own certificate chain during TLS negotiation and should fail negotiation
   * if no certificate chain was provided.  This will be ignored for
   * non-TLS-based connections, and it will also be ignored if
   * {@link #requestClientCertificate} returns false.
   *
   * @param  requireClientCertificate  Indicates whether the listener should
   *                                   require that the client present its own
   *                                   certificate chain during TLS negotiation.
   */
  public void setRequireClientCertificate(
                   final boolean requireClientCertificate)
  {
    this.requireClientCertificate = requireClientCertificate;
  }



/**
   * Creates a copy of this configuration that may be altered without impacting
   * this configuration, and which will not be altered by changes to this
   * configuration.
   *
   * @return  A copy of this configuration that may be altered without impacting
   *          this configuration, and which will not be altered by changes to
   *          this configuration.
   */
  @NotNull()
  public LDAPListenerConfig duplicate()
  {
    final LDAPListenerConfig copy =
         new LDAPListenerConfig(listenPort, requestHandler);

    copy.requestClientCertificate = requestClientCertificate;
    copy.requireClientCertificate = requireClientCertificate;
    copy.useKeepAlive             = useKeepAlive;
    copy.useLinger                = useLinger;
    copy.useReuseAddress          = useReuseAddress;
    copy.useTCPNoDelay            = useTCPNoDelay;
    copy.listenAddress            = listenAddress;
    copy.lingerTimeout            = lingerTimeout;
    copy.maxConnections           = maxConnections;
    copy.maxMessageSizeBytes      = maxMessageSizeBytes;
    copy.receiveBufferSize        = receiveBufferSize;
    copy.sendBufferSize           = sendBufferSize;
    copy.exceptionHandler         = exceptionHandler;
    copy.serverSocketFactory      = serverSocketFactory;

    return copy;
  }



  /**
   * Retrieves a string representation of this LDAP listener config.
   *
   * @return  A string representation of this LDAP listener config.
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
   * Appends a string representation of this LDAP listener config to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPListenerConfig(listenAddress=");

    if (listenAddress == null)
    {
      buffer.append("null");
    }
    else
    {
      buffer.append('\'');
      buffer.append(listenAddress.getHostAddress());
      buffer.append('\'');
    }

    buffer.append(", listenPort=");
    buffer.append(listenPort);
    buffer.append(", requestHandlerClass='");
    buffer.append(requestHandler.getClass().getName());
    buffer.append("', serverSocketFactoryClass='");
    buffer.append(serverSocketFactory.getClass().getName());
    buffer.append('\'');

    if (exceptionHandler != null)
    {
      buffer.append(", exceptionHandlerClass='");
      buffer.append(exceptionHandler.getClass().getName());
      buffer.append('\'');
    }

    buffer.append(", useKeepAlive=");
    buffer.append(useKeepAlive);
    buffer.append(", useTCPNoDelay=");
    buffer.append(useTCPNoDelay);

    if (useLinger)
    {
      buffer.append(", useLinger=true, lingerTimeout=");
      buffer.append(lingerTimeout);
    }
    else
    {
      buffer.append(", useLinger=false");
    }

    buffer.append(", maxConnections=");
    buffer.append(maxConnections);
    buffer.append(", maxMessageSizeBytes=");
    buffer.append(maxMessageSizeBytes);
    buffer.append(", useReuseAddress=");
    buffer.append(useReuseAddress);
    buffer.append(", receiveBufferSize=");
    buffer.append(receiveBufferSize);
    buffer.append(", sendBufferSize=");
    buffer.append(sendBufferSize);
    buffer.append(", requestClientCertificate=");
    buffer.append(requestClientCertificate);
    buffer.append(", requireClientCertificate=");
    buffer.append(requireClientCertificate);
    buffer.append(')');
  }
}
