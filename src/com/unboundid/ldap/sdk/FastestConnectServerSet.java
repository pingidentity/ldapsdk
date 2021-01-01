/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.SocketFactory;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a server set implementation that will attempt to
 * establish connections to all associated servers in parallel, keeping the one
 * that was first to be successfully established and closing all others.
 * <BR><BR>
 * Note that this server set implementation may only be used in conjunction with
 * connection options that allow the associated socket factory to create
 * multiple connections in parallel.  If the
 * {@link LDAPConnectionOptions#allowConcurrentSocketFactoryUse} method returns
 * false for the associated connection options, then the {@code getConnection}
 * methods will throw an exception.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for creating a fastest connect
 * server set that may be used to establish connections to either of two
 * servers.  When using the server set to attempt to create a connection, it
 * will try both in parallel and will return the first connection that it is
 * able to establish:
 * <PRE>
 * // Create arrays with the addresses and ports of the directory server
 * // instances.
 * String[] addresses =
 * {
 *   server1Address,
 *   server2Address
 * };
 * int[] ports =
 * {
 *   server1Port,
 *   server2Port
 * };
 *
 * // Create the server set using the address and port arrays.
 * FastestConnectServerSet fastestConnectSet =
 *      new FastestConnectServerSet(addresses, ports);
 *
 * // Verify that we can establish a single connection using the server set.
 * LDAPConnection connection = fastestConnectSet.getConnection();
 * RootDSE rootDSEFromConnection = connection.getRootDSE();
 * connection.close();
 *
 * // Verify that we can establish a connection pool using the server set.
 * SimpleBindRequest bindRequest =
 *      new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
 * LDAPConnectionPool pool =
 *      new LDAPConnectionPool(fastestConnectSet, bindRequest, 10);
 * RootDSE rootDSEFromPool = pool.getRootDSE();
 * pool.close();
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FastestConnectServerSet
       extends ServerSet
{
  // The bind request to use to authenticate connections created by this
  // server set.
  @Nullable private final BindRequest bindRequest;

  // The port numbers of the target servers.
  @NotNull private final int[] ports;

  // The set of connection options to use for new connections.
  @NotNull private final LDAPConnectionOptions connectionOptions;

  // The post-connect processor to invoke against connections created by this
  // server set.
  @Nullable private final PostConnectProcessor postConnectProcessor;

  // The socket factory to use to establish connections.
  @NotNull private final SocketFactory socketFactory;

  // The addresses of the target servers.
  @NotNull private final String[] addresses;



  /**
   * Creates a new fastest connect server set with the specified set of
   * directory server addresses and port numbers.  It will use the default
   * socket factory provided by the JVM to create the underlying sockets.
   *
   * @param  addresses  The addresses of the directory servers to which the
   *                    connections should be established.  It must not be
   *                    {@code null} or empty.
   * @param  ports      The ports of the directory servers to which the
   *                    connections should be established.  It must not be
   *                    {@code null}, and it must have the same number of
   *                    elements as the {@code addresses} array.  The order of
   *                    elements in the {@code addresses} array must correspond
   *                    to the order of elements in the {@code ports} array.
   */
  public FastestConnectServerSet(@NotNull final String[] addresses,
                                 @NotNull final int[] ports)
  {
    this(addresses, ports, null, null);
  }



  /**
   * Creates a new fastest connect server set with the specified set of
   * directory server addresses and port numbers.  It will use the default
   * socket factory provided by the JVM to create the underlying sockets.
   *
   * @param  addresses          The addresses of the directory servers to which
   *                            the connections should be established.  It must
   *                            not be {@code null} or empty.
   * @param  ports              The ports of the directory servers to which the
   *                            connections should be established.  It must not
   *                            be {@code null}, and it must have the same
   *                            number of elements as the {@code addresses}
   *                            array.  The order of elements in the
   *                            {@code addresses} array must correspond to the
   *                            order of elements in the {@code ports} array.
   * @param  connectionOptions  The set of connection options to use for the
   *                            underlying connections.
   */
  public FastestConnectServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, null, connectionOptions);
  }



  /**
   * Creates a new fastest connect server set with the specified set of
   * directory server addresses and port numbers.  It will use the provided
   * socket factory to create the underlying sockets.
   *
   * @param  addresses      The addresses of the directory servers to which the
   *                        connections should be established.  It must not be
   *                        {@code null} or empty.
   * @param  ports          The ports of the directory servers to which the
   *                        connections should be established.  It must not be
   *                        {@code null}, and it must have the same number of
   *                        elements as the {@code addresses} array.  The order
   *                        of elements in the {@code addresses} array must
   *                        correspond to the order of elements in the
   *                        {@code ports} array.
   * @param  socketFactory  The socket factory to use to create the underlying
   *                        connections.
   */
  public FastestConnectServerSet(@NotNull final String[] addresses,
                                 @NotNull final int[] ports,
                                 @Nullable final SocketFactory socketFactory)
  {
    this(addresses, ports, socketFactory, null);
  }



  /**
   * Creates a new fastest connect server set with the specified set of
   * directory server addresses and port numbers.  It will use the provided
   * socket factory to create the underlying sockets.
   *
   * @param  addresses          The addresses of the directory servers to which
   *                            the connections should be established.  It must
   *                            not be {@code null} or empty.
   * @param  ports              The ports of the directory servers to which the
   *                            connections should be established.  It must not
   *                            be {@code null}, and it must have the same
   *                            number of elements as the {@code addresses}
   *                            array.  The order of elements in the
   *                            {@code addresses} array must correspond to the
   *                            order of elements in the {@code ports} array.
   * @param  socketFactory      The socket factory to use to create the
   *                            underlying connections.
   * @param  connectionOptions  The set of connection options to use for the
   *                            underlying connections.
   */
  public FastestConnectServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, socketFactory, connectionOptions, null, null);
  }



  /**
   * Creates a new fastest connect server set with the specified set of
   * directory server addresses and port numbers.  It will use the provided
   * socket factory to create the underlying sockets.
   *
   * @param  addresses             The addresses of the directory servers to
   *                               which the connections should be established.
   *                               It must not be {@code null} or empty.
   * @param  ports                 The ports of the directory servers to which
   *                               the connections should be established.  It
   *                               must not be {@code null}, and it must have
   *                               the same number of elements as the
   *                               {@code addresses} array.  The order of
   *                               elements in the {@code addresses} array must
   *                               correspond to the order of elements in the
   *                               {@code ports} array.
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
  public FastestConnectServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions,
              @Nullable final BindRequest bindRequest,
              @Nullable final PostConnectProcessor postConnectProcessor)
  {
    Validator.ensureNotNull(addresses, ports);
    Validator.ensureTrue(addresses.length > 0,
         "RoundRobinServerSet.addresses must not be empty.");
    Validator.ensureTrue(addresses.length == ports.length,
         "RoundRobinServerSet addresses and ports arrays must be the same " +
              "size.");

    this.addresses = addresses;
    this.ports = ports;
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
   * Retrieves the addresses of the directory servers to which the connections
   * should be established.
   *
   * @return  The addresses of the directory servers to which the connections
   *          should be established.
   */
  @NotNull()
  public String[] getAddresses()
  {
    return addresses;
  }



  /**
   * Retrieves the ports of the directory servers to which the connections
   * should be established.
   *
   * @return  The ports of the directory servers to which the connections should
   *          be established.
   */
  @NotNull()
  public int[] getPorts()
  {
    return ports;
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
   * Retrieves the set of connection options that will be used for underlying
   * connections.
   *
   * @return  The set of connection options that will be used for underlying
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
    if (! connectionOptions.allowConcurrentSocketFactoryUse())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_FASTEST_CONNECT_SET_OPTIONS_NOT_PARALLEL.get());
    }

    final ArrayBlockingQueue<Object> resultQueue =
         new ArrayBlockingQueue<>(addresses.length, false);
    final AtomicBoolean connectionSelected = new AtomicBoolean(false);

    final FastestConnectThread[] connectThreads =
         new FastestConnectThread[addresses.length];
    for (int i=0; i < connectThreads.length; i++)
    {
      connectThreads[i] = new FastestConnectThread(addresses[i], ports[i],
           socketFactory, connectionOptions, bindRequest, postConnectProcessor,
           healthCheck, resultQueue, connectionSelected);
    }

    for (final FastestConnectThread t : connectThreads)
    {
      t.start();
    }

    try
    {
      final long effectiveConnectTimeout;
      final long connectTimeout =
           connectionOptions.getConnectTimeoutMillis();
      if ((connectTimeout > 0L) && (connectTimeout < Integer.MAX_VALUE))
      {
        effectiveConnectTimeout = connectTimeout;
      }
      else
      {
        effectiveConnectTimeout = Integer.MAX_VALUE;
      }

      int connectFailures = 0;
      final long stopWaitingTime =
           System.currentTimeMillis() + effectiveConnectTimeout;
      while (true)
      {
        final Object o;
        final long waitTime = stopWaitingTime - System.currentTimeMillis();
        if (waitTime > 0L)
        {
          o = resultQueue.poll(waitTime, TimeUnit.MILLISECONDS);
        }
        else
        {
          o = resultQueue.poll();
        }

        if (o == null)
        {
          throw new LDAPException(ResultCode.CONNECT_ERROR,
               ERR_FASTEST_CONNECT_SET_CONNECT_TIMEOUT.get(
                    effectiveConnectTimeout));
        }
        else if (o instanceof LDAPConnection)
        {
          final LDAPConnection conn = (LDAPConnection) o;
          associateConnectionWithThisServerSet(conn);
          return conn;
        }
        else
        {
          connectFailures++;
          if (connectFailures >= addresses.length)
          {
            throw new LDAPException(ResultCode.CONNECT_ERROR,
                 ERR_FASTEST_CONNECT_SET_ALL_FAILED.get());
          }
        }
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }

      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_FASTEST_CONNECT_SET_CONNECT_EXCEPTION.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("FastestConnectServerSet(servers={");

    for (int i=0; i < addresses.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(addresses[i]);
      buffer.append(':');
      buffer.append(ports[i]);
    }

    buffer.append("}, includesAuthentication=");
    buffer.append(bindRequest != null);
    buffer.append(", includesPostConnectProcessing=");
    buffer.append(postConnectProcessor != null);
    buffer.append(')');
  }
}
