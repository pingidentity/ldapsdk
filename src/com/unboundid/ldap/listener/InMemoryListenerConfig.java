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
package com.unboundid.ldap.listener;



import java.net.InetAddress;
import javax.net.SocketFactory;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a data structure that can be used to configure a
 * listener for use in the in-memory directory server.  Each in-memory directory
 * server instance has the ability to have multiple listeners, and those
 * listeners may have different settings (e.g., listen on one port for
 * unencrypted LDAP communication with optional support for StartTLS, and listen
 * on a separate port for SSL-encrypted communication).  If the server is to
 * provide support for SSL and/or StartTLS, then the {@link SSLUtil} class can
 * make it easy to create the necessary socket factories.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InMemoryListenerConfig
{
  // Indicates whether the listener should request that the client provide a
  // certificate.
  private final boolean requestClientCertificate;

  // Indicates whether the listener should require that the client provide a
  // certificate.
  private final boolean requireClientCertificate;

  // The address on which this listener should accept client connections.
  @Nullable private final InetAddress listenAddress;

  // The port on which this listener should accept client connections.
  private final int listenPort;

  // The socket factory that should be used for accepting new connections.
  @Nullable private final ServerSocketFactory serverSocketFactory;

  // The socket factory that should be used for creating client connections.
  @Nullable private final SocketFactory clientSocketFactory;

  // The socket factory that will be used to add StartTLS encryption to an
  // existing connection.
  @Nullable private final SSLSocketFactory startTLSSocketFactory;

  // The used to refer to this listener.
  @NotNull private final String listenerName;



  /**
   * Creates a new in-memory directory server listener configuration with the
   * provided settings.
   *
   * @param  listenerName           The name to assign to this listener.  It
   *                                must not be {@code null} and must not be the
   *                                same as the name for any other listener
   *                                configured in the server.
   * @param  listenAddress          The address on which the listener should
   *                                accept connections from clients.  It may be
   *                                {@code null} to indicate that it should
   *                                accept connections on all addresses on all
   *                                interfaces.
   * @param  listenPort             The port on which the listener should accept
   *                                connections from clients.  It may be 0 to
   *                                indicate that the server should
   *                                automatically choose an available port.
   * @param  serverSocketFactory    The socket factory that should be used to
   *                                create sockets when accepting client
   *                                connections.  It may be {@code null} if the
   *                                JVM-default server socket factory should be
   *                                used.
   * @param  clientSocketFactory    The socket factory that should be used to
   *                                create client connections to the server.  It
   *                                may be {@code null} if the JVM-default
   *                                socket factory should be used.
   * @param  startTLSSocketFactory  The socket factory that should be used to
   *                                add StartTLS encryption to existing
   *                                connections.  It may be {@code null} if
   *                                StartTLS is not to be supported on this
   *                                listener, and should be {@code null} if the
   *                                server socket factory already provides some
   *                                other form of communication security.
   *
   * @throws  LDAPException  If the provided listener name is {@code null} or
   *                         the configured listen port is out of range.
   */
  public InMemoryListenerConfig(@NotNull final String listenerName,
              @Nullable final InetAddress listenAddress, final int listenPort,
              @Nullable final ServerSocketFactory serverSocketFactory,
              @Nullable final SocketFactory clientSocketFactory,
              @Nullable final SSLSocketFactory startTLSSocketFactory)
         throws LDAPException
  {
    this(listenerName, listenAddress, listenPort, serverSocketFactory,
         clientSocketFactory, startTLSSocketFactory, false, false);
  }



  /**
   * Creates a new in-memory directory server listener configuration with the
   * provided settings.
   *
   * @param  listenerName              The name to assign to this listener.  It
   *                                   must not be {@code null} and must not be
   *                                   the same as the name for any other
   *                                   listener configured in the server.
   * @param  listenAddress             The address on which the listener should
   *                                   accept connections from clients.  It may
   *                                   be {@code null} to indicate that it
   *                                   should accept connections on all
   *                                   addresses on all interfaces.
   * @param  listenPort                The port on which the listener should
   *                                   accept connections from clients.  It may
   *                                   be 0 to indicate that the server should
   *                                   automatically choose an available port.
   * @param  serverSocketFactory       The socket factory that should be used to
   *                                   create sockets when accepting client
   *                                   connections.  It may be {@code null} if
   *                                   the JVM-default server socket factory
   *                                   should be used.
   * @param  clientSocketFactory       The socket factory that should be used to
   *                                   create client connections to the server.
   *                                   It may be {@code null} if the JVM-default
   *                                   socket factory should be used.
   * @param  startTLSSocketFactory     The socket factory that should be used to
   *                                   add StartTLS encryption to existing
   *                                   connections.  It may be {@code null} if
   *                                   StartTLS is not to be supported on this
   *                                   listener, and should be {@code null} if
   *                                   the server socket factory already
   *                                   provides some other form of communication
   *                                   security.
   * @param  requestClientCertificate  Indicates whether the listener should
   *                                   request that the client present its own
   *                                   certificate chain during TLS negotiation.
   *                                   This will be ignored for non-TLS-based
   *                                   connections.
   * @param  requireClientCertificate  Indicates whether the listener should
   *                                   require that the client present its own
   *                                   certificate chain during TLS negotiation,
   *                                   and should fail negotiation if the client
   *                                   does not present one.  This will be
   *                                   ignored for non-TLS-based connections or
   *                                   if {@code requestClientCertificate} is
   *                                   {@code false}.
   *
   * @throws  LDAPException  If the provided listener name is {@code null} or
   *                         the configured listen port is out of range.
   */
  public InMemoryListenerConfig(@NotNull final String listenerName,
              @Nullable final InetAddress listenAddress, final int listenPort,
              @Nullable final ServerSocketFactory serverSocketFactory,
              @Nullable final SocketFactory clientSocketFactory,
              @Nullable final SSLSocketFactory startTLSSocketFactory,
              final boolean requestClientCertificate,
              final boolean requireClientCertificate)
         throws LDAPException
  {
    if ((listenerName == null) || listenerName.isEmpty())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LISTENER_CFG_NO_NAME.get());
    }

    if ((listenPort < 0) || (listenPort > 65_535))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LISTENER_CFG_INVALID_PORT.get(listenPort));
    }

    this.listenerName             = listenerName;
    this.listenAddress            = listenAddress;
    this.listenPort               = listenPort;
    this.serverSocketFactory      = serverSocketFactory;
    this.clientSocketFactory      = clientSocketFactory;
    this.startTLSSocketFactory    = startTLSSocketFactory;
    this.requestClientCertificate = requestClientCertificate;
    this.requireClientCertificate = requireClientCertificate;
  }



  /**
   * Creates a new listener configuration that will listen for unencrypted LDAP
   * communication on an automatically-selected port on all available addresses.
   * It will not support StartTLS.
   *
   * @param  listenerName  The name to use for the listener.  It must not be
   *                       {@code null}.
   *
   * @return  The newly-created listener configuration.
   *
   * @throws  LDAPException  If the provided name is {@code null}.
   */
  @NotNull()
  public static InMemoryListenerConfig createLDAPConfig(
                                            @NotNull final String listenerName)
         throws LDAPException
  {
    return new InMemoryListenerConfig(listenerName, null, 0, null, null, null);
  }



  /**
   * Creates a new listener configuration that will listen for unencrypted LDAP
   * communication on the specified port on all available addresses.  It will
   * not support StartTLS.
   *
   * @param  listenerName  The name to use for the listener.  It must not be
   *                       {@code null}.
   * @param  listenPort    The port on which the listener should accept
   *                       connections from clients.  It may be 0 to indicate
   *                       that the server should automatically choose an
   *                       available port.
   *
   * @return  The newly-created listener configuration.
   *
   * @throws  LDAPException  If the provided listener name is {@code null} or
   *                         the configured listen port is out of range.
   */
  @NotNull()
  public static InMemoryListenerConfig createLDAPConfig(
                                            @NotNull final String listenerName,
                                            final int listenPort)
         throws LDAPException
  {
    return new InMemoryListenerConfig(listenerName, null, listenPort, null,
         null, null);
  }



  /**
   * Creates a new listener configuration that will listen for unencrypted LDAP
   * communication, and may optionally support StartTLS.
   *
   * @param  listenerName           The name to assign to this listener.  It
   *                                must not be {@code null} and must not be the
   *                                same as the name for any other listener
   *                                configured in the server.
   * @param  listenAddress          The address on which the listener should
   *                                accept connections from clients.  It may be
   *                                {@code null} to indicate that it should
   *                                accept connections on all addresses on all
   *                                interfaces.
   * @param  listenPort             The port on which the listener should accept
   *                                connections from clients.  It may be 0 to
   *                                indicate that the server should
   *                                automatically choose an available port.
   * @param  startTLSSocketFactory  The socket factory that should be used to
   *                                add StartTLS encryption to an existing
   *                                connection.  It may be {@code null} if
   *                                StartTLS is not to be supported on this
   *                                listener, and should be {@code null} if the
   *                                server socket factory already provides some
   *                                other form of communication security.
   *
   * @return  The newly-created listener configuration.
   *
   * @throws  LDAPException  If the provided listener name is {@code null} or
   *                         the configured listen port is out of range.
   */
  @NotNull()
  public static InMemoryListenerConfig createLDAPConfig(
                     @NotNull final String listenerName,
                     @Nullable final InetAddress listenAddress,
                     final int listenPort,
                     @Nullable final SSLSocketFactory startTLSSocketFactory)
         throws LDAPException
  {
    return createLDAPConfig(listenerName, listenAddress, listenPort,
         startTLSSocketFactory, false, false);
  }



  /**
   * Creates a new listener configuration that will listen for unencrypted LDAP
   * communication, and may optionally support StartTLS.
   *
   * @param  listenerName              The name to assign to this listener.  It
   *                                   must not be {@code null} and must not be
   *                                   the same as the name for any other
   *                                   listener configured in the server.
   * @param  listenAddress             The address on which the listener should
   *                                   accept connections from clients.  It may
   *                                   be {@code null} to indicate that it
   *                                   should accept connections on all
   *                                   addresses on all interfaces.
   * @param  listenPort                The port on which the listener should
   *                                   accept connections from clients.  It may
   *                                   be 0 to indicate that the server should
   *                                   automatically choose an available port.
   * @param  startTLSSocketFactory     The socket factory that should be used to
   *                                   add StartTLS encryption to an existing
   *                                   connection.  It may be {@code null} if
   *                                   StartTLS is not to be supported on this
   *                                   listener, and should be {@code null} if
   *                                   the server socket factory already
   *                                   provides some other form of communication
   *                                   security.
   * @param  requestClientCertificate  Indicates whether the listener should
   *                                   request that the client present its own
   *                                   certificate chain during TLS negotiation.
   *                                   This will be ignored for non-TLS-based
   *                                   connections.
   * @param  requireClientCertificate  Indicates whether the listener should
   *                                   require that the client present its own
   *                                   certificate chain during TLS negotiation,
   *                                   and should fail negotiation if the client
   *                                   does not present one.  This will be
   *                                   ignored for non-TLS-based connections or
   *                                   if {@code requestClientCertificate} is
   *                                   {@code false}.
   *
   * @return  The newly-created listener configuration.
   *
   * @throws  LDAPException  If the provided listener name is {@code null} or
   *                         the configured listen port is out of range.
   */
  @NotNull()
  public static InMemoryListenerConfig createLDAPConfig(
                     @NotNull final String listenerName,
                     @Nullable final InetAddress listenAddress,
                     final int listenPort,
                     @Nullable final SSLSocketFactory startTLSSocketFactory,
                     final boolean requestClientCertificate,
                     final boolean requireClientCertificate)
         throws LDAPException
  {
    return new InMemoryListenerConfig(listenerName, listenAddress, listenPort,
         null, null, startTLSSocketFactory, requestClientCertificate,
         requireClientCertificate);
  }



  /**
   * Creates a new listener configuration that will listen for SSL-encrypted
   * LDAP communication on an automatically-selected port on all available
   * addresses.
   *
   * @param  listenerName         The name to use for the listener.  It must not
   *                              be {@code null}.
   * @param  serverSocketFactory  The SSL server socket factory that will be
   *                              used for accepting SSL-based connections from
   *                              clients.  It must not be {@code null}.
   *
   * @return  The newly-created listener configuration.
   *
   * @throws  LDAPException  If the provided name is {@code null}.
   */
  @NotNull()
  public static InMemoryListenerConfig createLDAPSConfig(
                     @NotNull final String listenerName,
                     @NotNull final SSLServerSocketFactory serverSocketFactory)
         throws LDAPException
  {
    return createLDAPSConfig(listenerName, null, 0, serverSocketFactory, null);
  }



  /**
   * Creates a new listener configuration that will listen for SSL-encrypted
   * LDAP communication on the specified port on all available addresses.
   *
   * @param  listenerName         The name to use for the listener.  It must not
   *                              be {@code null}.
   * @param  listenPort           The port on which the listener should accept
   *                              connections from clients.  It may be 0 to
   *                              indicate that the server should
   *                              automatically choose an available port.
   * @param  serverSocketFactory  The SSL server socket factory that will be
   *                              used for accepting SSL-based connections from
   *                              clients.  It must not be {@code null}.
   *
   * @return  The newly-created listener configuration.
   *
   * @throws  LDAPException  If the provided name is {@code null}.
   */
  @NotNull()
  public static InMemoryListenerConfig createLDAPSConfig(
                     @NotNull final String listenerName, final int listenPort,
                     @NotNull final SSLServerSocketFactory serverSocketFactory)
         throws LDAPException
  {
    return createLDAPSConfig(listenerName, null, listenPort,
         serverSocketFactory, null);
  }



  /**
   * Creates a new listener configuration that will listen for SSL-encrypted
   * LDAP communication on an automatically-selected port on all available
   * addresses.
   *
   * @param  listenerName         The name to use for the listener.  It must not
   *                              be {@code null}.
   * @param  listenAddress        The address on which the listener should
   *                              accept connections from clients.  It may be
   *                              {@code null} to indicate that it should
   *                              accept connections on all addresses on all
   *                              interfaces.
   * @param  listenPort           The port on which the listener should accept
   *                              connections from clients.  It may be 0 to
   *                              indicate that the server should
   *                              automatically choose an available port.
   * @param  serverSocketFactory  The SSL server socket factory that will be
   *                              used for accepting SSL-based connections from
   *                              clients.  It must not be {@code null}.
   * @param  clientSocketFactory  The SSL socket factory that will be used to
   *                              create secure connections to the server.  It
   *                              may be {@code null} if a default "trust all"
   *                              socket factory should be used.
   *
   * @return  The newly-created listener configuration.
   *
   * @throws  LDAPException  If the provided name or server socket factory is
   *          {@code null}, or an error occurs while attempting to create a
   *          client socket factory.
   */
  @NotNull()
  public static InMemoryListenerConfig createLDAPSConfig(
                     @NotNull final String listenerName,
                     @Nullable final InetAddress listenAddress,
                     final int listenPort,
                     @NotNull final SSLServerSocketFactory serverSocketFactory,
                     @Nullable final SSLSocketFactory clientSocketFactory)
         throws LDAPException
  {
    return createLDAPSConfig(listenerName, listenAddress, listenPort,
         serverSocketFactory, clientSocketFactory, false, false);
  }



  /**
   * Creates a new listener configuration that will listen for SSL-encrypted
   * LDAP communication on an automatically-selected port on all available
   * addresses.
   *
   * @param  listenerName              The name to use for the listener.  It
   *                                   must not be {@code null}.
   * @param  listenAddress             The address on which the listener should
   *                                   accept connections from clients.  It may
   *                                   be  {@code null} to indicate that it
   *                                   should accept connections on all
   *                                   addresses on all interfaces.
   * @param  listenPort                The port on which the listener should
   *                                   accept connections from clients.  It may
   *                                   be 0 to indicate that the server should
   *                                   automatically choose an available port.
   * @param  serverSocketFactory       The SSL server socket factory that will
   *                                   be used for accepting SSL-based
   *                                   connections from clients.  It must not be
   *                                   {@code null}.
   * @param  clientSocketFactory       The SSL socket factory that will be used
   *                                   to create secure connections to the
   *                                   server.  It may be {@code null} if a
   *                                   default "trust all" socket factory should
   *                                   be used.
   * @param  requestClientCertificate  Indicates whether the listener should
   *                                   request that the client present its own
   *                                   certificate chain during TLS negotiation.
   *                                   This will be ignored for non-TLS-based
   *                                   connections.
   * @param  requireClientCertificate  Indicates whether the listener should
   *                                   require that the client present its own
   *                                   certificate chain during TLS negotiation,
   *                                   and should fail negotiation if the client
   *                                   does not present one.  This will be
   *                                   ignored for non-TLS-based connections or
   *                                   if {@code requestClientCertificate} is
   *                                   {@code false}.
   *
   * @return  The newly-created listener configuration.
   *
   * @throws  LDAPException  If the provided name or server socket factory is
   *          {@code null}, or an error occurs while attempting to create a
   *          client socket factory.
   */
  @NotNull()
  public static InMemoryListenerConfig createLDAPSConfig(
                     @NotNull final String listenerName,
                     @Nullable final InetAddress listenAddress,
                     final int listenPort,
                     @NotNull final SSLServerSocketFactory serverSocketFactory,
                     @Nullable final SSLSocketFactory clientSocketFactory,
                     final boolean requestClientCertificate,
                     final boolean requireClientCertificate)
         throws LDAPException
  {
    if (serverSocketFactory == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LISTENER_CFG_NO_SSL_SERVER_SOCKET_FACTORY.get());
    }

    final SSLSocketFactory clientFactory;
    if (clientSocketFactory == null)
    {
      try
      {
        final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
        clientFactory = sslUtil.createSSLSocketFactory();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LISTENER_CFG_COULD_NOT_CREATE_SSL_SOCKET_FACTORY.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    else
    {
      clientFactory = clientSocketFactory;
    }

    return new InMemoryListenerConfig(listenerName, listenAddress, listenPort,
         serverSocketFactory, clientFactory, null, requestClientCertificate,
         requireClientCertificate);
  }



  /**
   * Retrieves the name for this listener configuration.
   *
   * @return  The name for this listener configuration.
   */
  @NotNull()
  public String getListenerName()
  {
    return listenerName;
  }



  /**
   * Retrieves the address on which the listener should accept connections from
   * clients, if defined.
   *
   * @return  The address on which the listener should accept connections from
   *          clients, or {@code null} if it should accept connections on all
   *          addresses on all interfaces.
   */
  @Nullable()
  public InetAddress getListenAddress()
  {
    return listenAddress;
  }



  /**
   * Retrieves the port on which the listener should accept connections from
   * clients, if defined.
   *
   * @return  The port on which the listener should accept connections from
   *          clients, or 0 if the listener should automatically select an
   *          available port.
   */
  public int getListenPort()
  {
    return listenPort;
  }



  /**
   * Retrieves the socket factory that should be used to create sockets when
   * accepting client connections, if defined.
   *
   * @return  The socket factory that should be used to create sockets when
   *          accepting client connections, or {@code null} if the JVM-default
   *          server socket factory should be used.
   */
  @Nullable()
  public ServerSocketFactory getServerSocketFactory()
  {
    return serverSocketFactory;
  }



  /**
   * Retrieves the socket factory that should be used to create client
   * connections to the server, if defined.
   *
   * @return  The socket factory that should be used to create client
   *          connections to the server, or {@code null} if the JVM-default
   *          socket factory should be used.
   */
  @Nullable()
  public SocketFactory getClientSocketFactory()
  {
    return clientSocketFactory;
  }



  /**
   * Retrieves the socket factory that should be used to add StartTLS encryption
   * to existing connections, if defined.
   *
   * @return  The socket factory that should be used to add StartTLS encryption
   *          to existing connections, or {@code null} if StartTLS should not be
   *          supported.
   */
  @Nullable()
  public SSLSocketFactory getStartTLSSocketFactory()
  {
    return startTLSSocketFactory;
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
   * Retrieves a string representation of this listener configuration.
   *
   * @return  A string representation of this listener configuration.
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
   * Appends a string representation of this listener configuration to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("InMemoryListenerConfig(name='");
    buffer.append(listenerName);
    buffer.append('\'');

    if (listenAddress != null)
    {
      buffer.append(", listenAddress='");
      buffer.append(listenAddress.getHostAddress());
      buffer.append('\'');
    }

    buffer.append(", listenPort=");
    buffer.append(listenPort);

    if (serverSocketFactory != null)
    {
      buffer.append(", serverSocketFactoryClass='");
      buffer.append(serverSocketFactory.getClass().getName());
      buffer.append('\'');
    }

    if (clientSocketFactory != null)
    {
      buffer.append(", clientSocketFactoryClass='");
      buffer.append(clientSocketFactory.getClass().getName());
      buffer.append('\'');
    }

    if (startTLSSocketFactory != null)
    {
      buffer.append(", startTLSSocketFactoryClass='");
      buffer.append(startTLSSocketFactory.getClass().getName());
      buffer.append('\'');
    }

    buffer.append(", requestClientCertificate=");
    buffer.append(requestClientCertificate);
    buffer.append(", requireClientCertificate=");
    buffer.append(requireClientCertificate);

    buffer.append(')');
  }
}
