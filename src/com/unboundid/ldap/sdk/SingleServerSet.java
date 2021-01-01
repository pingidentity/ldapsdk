/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import javax.net.SocketFactory;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a server set implementation that only provides the
 * ability to connect to a single server.  It may be used in cases where a
 * {@link ServerSet} is required but only a single server is needed.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SingleServerSet
       extends ServerSet
{
  // The bind request to use to authenticate connections created by this
  // server set.
  @Nullable private final BindRequest bindRequest;

  // The port number of the target server.
  private final int port;

  // The set of connection options to use.
  @NotNull private final LDAPConnectionOptions connectionOptions;

  // The post-connect processor to invoke against connections created by this
  // server set.
  @Nullable private final PostConnectProcessor postConnectProcessor;

  // The socket factory to use to establish connections.
  @NotNull private final SocketFactory socketFactory;

  // The address of the target server.
  @NotNull private final String address;



  /**
   * Creates a new single server set with the specified address and port.  It
   * will use the default socket factory provided by the JVM to create the
   * underlying socket.
   *
   * @param  address  The address of the directory server to which the
   *                  connections should be established.  It must not be
   *                  {@code null}.
   * @param  port     The port of the directory server to which the connections
   *                  should be established.  It must be between 1 and 65535,
   *                  inclusive.
   */
  public SingleServerSet(@NotNull final String address, final int port)
  {
    this(address, port, null, null);
  }



  /**
   * Creates a new single server set with the specified address and port.  It
   * will use the default socket factory provided by the JVM to create the
   * underlying socket.
   *
   * @param  address            The address of the directory server to which the
   *                            connections should be established.  It must not
   *                            be {@code null}.
   * @param  port               The port of the directory server to which the
   *                            connections should be established.  It must be
   *                            between 1 and 65535, inclusive.
   * @param  connectionOptions  The set of connection options to use for the
   *                            underlying connections.
   */
  public SingleServerSet(@NotNull final String address, final int port,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(address, port, null, connectionOptions);
  }



  /**
   * Creates a new single server set with the specified address and port, and
   * using the provided socket factory.
   *
   * @param  address        The address of the directory server to which the
   *                        connections should be established.  It must not be
   *                        {@code null}.
   * @param  port           The port of the directory server to which the
   *                        connections should be established.  It must be
   *                        between 1 and 65535, inclusive.
   * @param  socketFactory  The socket factory to use to create the underlying
   *                        connections.
   */
  public SingleServerSet(@NotNull final String address, final int port,
                         @Nullable final SocketFactory socketFactory)
  {
    this(address, port, socketFactory, null);
  }



  /**
   * Creates a new single server set with the specified address and port, and
   * using the provided socket factory.
   *
   * @param  address            The address of the directory server to which the
   *                            connections should be established.  It must not
   *                            be {@code null}.
   * @param  port               The port of the directory server to which the
   *                            connections should be established.  It must be
   *                            between 1 and 65535, inclusive.
   * @param  socketFactory      The socket factory to use to create the
   *                            underlying connections.
   * @param  connectionOptions  The set of connection options to use for the
   *                            underlying connections.
   */
  public SingleServerSet(@NotNull final String address, final int port,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(address, port, socketFactory, connectionOptions, null, null);
  }



  /**
   * Creates a new single server set with the specified address and port, and
   * using the provided socket factory.
   *
   * @param  address               The address of the directory server to which
   *                               the connections should be established.  It
   *                               must not be {@code null}.
   * @param  port                  The port of the directory server to which the
   *                               connections should be established.  It must
   *                               be between 1 and 65535, inclusive.
   * @param  socketFactory         The socket factory to use to create the
   *                               underlying connections.
   * @param  connectionOptions     The set of connection options to use for the
   *                               underlying connections.
   * @param  bindRequest           The bind request that should be used to
   *                               authenticate newly-established connections.
   *                               It may be {@code null} if this server set
   *                               should not perform any authentication.
   * @param  postConnectProcessor  The post-connect processor that should be
   *                               invoked on newly-established connections.  It
   *                               may be {@code null} if this server set should
   *                               not perform any post-connect processing.
   */
  public SingleServerSet(@NotNull final String address, final int port,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions,
              @Nullable final BindRequest bindRequest,
              @Nullable final PostConnectProcessor postConnectProcessor)
  {
    Validator.ensureNotNull(address);
    Validator.ensureTrue((port > 0) && (port < 65_536),
         "SingleServerSet.port must be between 1 and 65535.");

    this.address = address;
    this.port = port;
    this.bindRequest = bindRequest;
    this.postConnectProcessor = postConnectProcessor;

    if (socketFactory == null)
    {
      this.socketFactory = SocketFactory.getDefault();
    }
    else
    {
      this.socketFactory = socketFactory;
    }

    if (connectionOptions == null)
    {
      this.connectionOptions = new LDAPConnectionOptions();
    }
    else
    {
      this.connectionOptions = connectionOptions;
    }
  }



  /**
   * Retrieves the address of the directory server to which the connections
   * should be established.
   *
   * @return  The address of the directory server to which the connections
   *          should be established.
   */
  @NotNull()
  public String getAddress()
  {
    return address;
  }



  /**
   * Retrieves the port of the directory server to which the connections should
   * be established.
   *
   * @return  The port of the directory server to which the connections should
   *          be established.
   */
  public int getPort()
  {
    return port;
  }



  /**
   * Retrieves the socket factory that will be used to establish connections.
   *
   * @return  The socket factory that will be used to establish connections.
   */
  @NotNull()
  public SocketFactory getSocketFactory()
  {
    return socketFactory;
  }



  /**
   * Retrieves the set of connection options that will be used by the underlying
   * connections.
   *
   * @return  The set of connection options that will be used by the underlying
   *          connections.
   */
  @NotNull()
  public LDAPConnectionOptions getConnectionOptions()
  {
    return connectionOptions;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean includesAuthentication()
  {
    return (bindRequest != null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean includesPostConnectProcessing()
  {
    return (postConnectProcessor != null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnection getConnection()
         throws LDAPException
  {
    return getConnection(null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnection getConnection(
              @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    final LDAPConnection connection =
         new LDAPConnection(socketFactory, connectionOptions, address, port);
    doBindPostConnectAndHealthCheckProcessing(connection, bindRequest,
         postConnectProcessor, healthCheck);
    associateConnectionWithThisServerSet(connection);
    return connection;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SingleServerSet(server=");
    buffer.append(address);
    buffer.append(':');
    buffer.append(port);
    buffer.append(", includesAuthentication=");
    buffer.append(bindRequest != null);
    buffer.append(", includesPostConnectProcessing=");
    buffer.append(postConnectProcessor != null);
    buffer.append(')');
  }
}
