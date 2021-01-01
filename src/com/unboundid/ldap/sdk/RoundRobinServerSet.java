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



import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.SocketFactory;

import com.unboundid.util.Debug;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a server set implementation that will use a round-robin
 * algorithm to select the server to which the connection should be established.
 * Any number of servers may be included in this server set, and each request
 * will attempt to retrieve a connection to the next server in the list,
 * circling back to the beginning of the list as necessary.  If a server is
 * unavailable when an attempt is made to establish a connection to it, then
 * the connection will be established to the next available server in the set.
 * <BR><BR>
 * This server set implementation has the ability to maintain a temporary
 * blacklist of servers that have been recently found to be unavailable or
 * unsuitable for use.  If an attempt to establish or authenticate a
 * connection fails, if post-connect processing fails for that connection, or if
 * health checking indicates that the connection is not suitable, then that
 * server may be placed on the blacklist so that it will only be tried as a last
 * resort after all non-blacklisted servers have been attempted.  The blacklist
 * will be checked at regular intervals to determine whether a server should be
 * re-instated to availability.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for creating a round-robin
 * server set that may be used to establish connections to either of two
 * servers.  When using the server set to attempt to create a connection, it
 * will first try one of the servers, but will fail over to the other if the
 * first one attempted is not available:
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
 * RoundRobinServerSet roundRobinSet =
 *      new RoundRobinServerSet(addresses, ports);
 *
 * // Verify that we can establish a single connection using the server set.
 * LDAPConnection connection = roundRobinSet.getConnection();
 * RootDSE rootDSEFromConnection = connection.getRootDSE();
 * connection.close();
 *
 * // Verify that we can establish a connection pool using the server set.
 * SimpleBindRequest bindRequest =
 *      new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
 * LDAPConnectionPool pool =
 *      new LDAPConnectionPool(roundRobinSet, bindRequest, 10);
 * RootDSE rootDSEFromPool = pool.getRootDSE();
 * pool.close();
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RoundRobinServerSet
       extends ServerSet
{
  /**
   * The name of a system property that can be used to override the default
   * blacklist check interval, in milliseconds.
   */
  @NotNull static final String
       PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS =
            RoundRobinServerSet.class.getName() +
                 ".defaultBlacklistCheckIntervalMillis";



  // A counter used to determine the next slot that should be used.
  @NotNull private final AtomicLong nextSlot;

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

  // The blacklist manager for this server set.
  @Nullable private final ServerSetBlacklistManager blacklistManager;

  // The socket factory to use to establish connections.
  @NotNull private final SocketFactory socketFactory;

  // The addresses of the target servers.
  @NotNull private final String[] addresses;



  /**
   * Creates a new round robin server set with the specified set of directory
   * server addresses and port numbers.  It will use the default socket factory
   * provided by the JVM to create the underlying sockets.
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
  public RoundRobinServerSet(@NotNull final String[] addresses,
                             @NotNull final int[] ports)
  {
    this(addresses, ports, null, null);
  }



  /**
   * Creates a new round robin server set with the specified set of directory
   * server addresses and port numbers.  It will use the default socket factory
   * provided by the JVM to create the underlying sockets.
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
  public RoundRobinServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, null, connectionOptions);
  }



  /**
   * Creates a new round robin server set with the specified set of directory
   * server addresses and port numbers.  It will use the provided socket factory
   * to create the underlying sockets.
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
  public RoundRobinServerSet(@NotNull final String[] addresses,
                             @NotNull final int[] ports,
                             @Nullable final SocketFactory socketFactory)
  {
    this(addresses, ports, socketFactory, null);
  }



  /**
   * Creates a new round robin server set with the specified set of directory
   * server addresses and port numbers.  It will use the provided socket factory
   * to create the underlying sockets.
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
  public RoundRobinServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, socketFactory, connectionOptions, null, null);
  }



  /**
   * Creates a new round robin server set with the specified set of directory
   * server addresses and port numbers.  It will use the provided socket factory
   * to create the underlying sockets.
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
   *                               authenticate newly established connections.
   *                               It may be {@code null} if this server set
   *                               should not perform any authentication.
   * @param  postConnectProcessor  The post-connect processor that should be
   *                               invoked on newly established connections.  It
   *                               may be {@code null} if this server set should
   *                               not perform any post-connect processing.
   */
  public RoundRobinServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions,
              @Nullable final BindRequest bindRequest,
              @Nullable final PostConnectProcessor postConnectProcessor)
  {
    this(addresses, ports, socketFactory, connectionOptions, bindRequest,
         postConnectProcessor, getDefaultBlacklistCheckIntervalMillis());
  }



  /**
   * Creates a new round robin server set with the specified set of directory
   * server addresses and port numbers.  It will use the provided socket factory
   * to create the underlying sockets.
   *
   * @param  addresses                     The addresses of the directory
   *                                       servers to which the connections
   *                                       should be established.  It must not
   *                                       be {@code null} or empty.
   * @param  ports                         The ports of the directory servers to
   *                                       which the connections should be
   *                                       established.  It must not be
   *                                       {@code null}, and it must have the
   *                                       same number of elements as the
   *                                       {@code addresses} array.  The order
   *                                       of elements in the {@code addresses}
   *                                       array must correspond to the order of
   *                                       elements in the {@code ports} array.
   * @param  socketFactory                 The socket factory to use to create
   *                                       the underlying connections.
   * @param  connectionOptions             The set of connection options to use
   *                                       for the underlying connections.
   * @param  bindRequest                   The bind request that should be used
   *                                       to authenticate newly established
   *                                       connections.  It may be {@code null}
   *                                       if this server set should not perform
   *                                       any authentication.
   * @param  postConnectProcessor          The post-connect processor that
   *                                       should be invoked on newly
   *                                       established connections.  It may be
   *                                       {@code null} if this server set
   *                                       should not perform any post-connect
   *                                       processing.
   * @param  blacklistCheckIntervalMillis  The length of time in milliseconds
   *                                       between checks of servers on the
   *                                       blacklist to determine whether they
   *                                       are once again suitable for use.  A
   *                                       value that is less than or equal to
   *                                       zero indicates that no blacklist
   *                                       should be maintained.
   */
  public RoundRobinServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions,
              @Nullable final BindRequest bindRequest,
              @Nullable final PostConnectProcessor postConnectProcessor,
              final long blacklistCheckIntervalMillis)
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

    nextSlot = new AtomicLong(0L);

    if (blacklistCheckIntervalMillis > 0L)
    {
      blacklistManager = new ServerSetBlacklistManager(this, socketFactory,
           connectionOptions, bindRequest, postConnectProcessor,
           blacklistCheckIntervalMillis);
    }
    else
    {
      blacklistManager = null;
    }
  }



  /**
   * Retrieves the default blacklist check interval (in milliseconds that should
   * be used if it is not specified.
   *
   * @return  The default blacklist check interval (in milliseconds that should
   *          be used if it is not specified.
   */
  private static long getDefaultBlacklistCheckIntervalMillis()
  {
    final String propertyValue = StaticUtils.getSystemProperty(
         PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS);
    if (propertyValue != null)
    {
      try
      {
        return Long.parseLong(propertyValue);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return 30_000L;
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
    final int initialSlotNumber =
         (int) (nextSlot.getAndIncrement() %  addresses.length);

    LDAPException lastException = null;
    List<ObjectPair<String,Integer>> blacklistedServers = null;
    for (int i=0; i < addresses.length; i++)
    {
      final int slotNumber = ((initialSlotNumber + i) % addresses.length);
      final String address = addresses[slotNumber];
      final int port = ports[slotNumber];
      if ((blacklistManager != null) &&
           blacklistManager.isBlacklisted(address, port))
      {
        if (blacklistedServers == null)
        {
          blacklistedServers = new ArrayList<>(addresses.length);
        }

        blacklistedServers.add(new ObjectPair<>(address, port));
        continue;
      }

      try
      {
        final LDAPConnection c = new LDAPConnection(socketFactory,
             connectionOptions, addresses[slotNumber], ports[slotNumber]);
        doBindPostConnectAndHealthCheckProcessing(c, bindRequest,
             postConnectProcessor, healthCheck);
        associateConnectionWithThisServerSet(c);
        return c;
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        lastException = e;
        if (blacklistManager != null)
        {
          blacklistManager.addToBlacklist(address, port, healthCheck);
        }
      }
    }


    // If we've gotten here, then we couldn't get a connection from a
    // non-blacklisted server.  If there were any blacklisted servers, then try
    // them as a last resort.
    if (blacklistedServers != null)
    {
      for (final ObjectPair<String,Integer> hostPort : blacklistedServers)
      {
        try
        {
          final LDAPConnection c = new LDAPConnection(socketFactory,
               connectionOptions, hostPort.getFirst(), hostPort.getSecond());
          doBindPostConnectAndHealthCheckProcessing(c, bindRequest,
               postConnectProcessor, healthCheck);
          associateConnectionWithThisServerSet(c);
          blacklistManager.removeFromBlacklist(hostPort);
          return c;
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          lastException = e;
        }
      }
    }


    // If we've gotten here, then we've failed to connect to any of the servers,
    // so propagate the last exception to the caller.
    throw lastException;
  }



  /**
   * Retrieves the blacklist manager for this server set.
   *
   * @return  The blacklist manager for this server set, or {@code null} if no
   *          blacklist will be maintained.
   */
  @Nullable()
  public ServerSetBlacklistManager getBlacklistManager()
  {
    return blacklistManager;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void shutDown()
  {
    if (blacklistManager != null)
    {
      blacklistManager.shutDown();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RoundRobinServerSet(servers={");

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
