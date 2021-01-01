/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.SocketFactory;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a server set implementation that will establish a
 * connection to the server with the fewest established connections previously
 * created by the same server set instance.  If there are multiple servers that
 * share the fewest number of established connections, the first one in the list
 * will be chosen.  If a server is unavailable when an attempt is made to
 * establish a connection to it, then the connection will be established to the
 * available server with the next fewest number of established connections.
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
 * Note that this server set implementation is primarily intended for use with
 * connection pools, but is also suitable for cases in which standalone
 * connections are created as long as there will not be any attempt to close the
 * connections when they are re-established.  It is not suitable for use in
 * connections that may be re-established one or more times after being closed.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for creating a fewest
 * connections server set that may be used to establish connections to either of
 * two servers.
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
 * FewestConnectionsServerSet fewestConnectionsSet =
 *      new FewestConnectionsServerSet(addresses, ports);
 *
 * // Verify that we can establish a single connection using the server set.
 * LDAPConnection connection = fewestConnectionsSet.getConnection();
 * RootDSE rootDSEFromConnection = connection.getRootDSE();
 * connection.close();
 *
 * // Verify that we can establish a connection pool using the server set.
 * SimpleBindRequest bindRequest =
 *      new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
 * LDAPConnectionPool pool =
 *      new LDAPConnectionPool(fewestConnectionsSet, bindRequest, 10);
 * RootDSE rootDSEFromPool = pool.getRootDSE();
 * pool.close();
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FewestConnectionsServerSet
       extends ServerSet
{
  /**
   * The name of a system property that can be used to override the default
   * blacklist check interval, in milliseconds.
   */
  @NotNull static final String
       PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS =
            FewestConnectionsServerSet.class.getName() +
                 ".defaultBlacklistCheckIntervalMillis";



  // The bind request to use to authenticate connections created by this
  // server set.
  @Nullable private final BindRequest bindRequest;

  // The set of connection options to use for new connections.
  @NotNull private final LDAPConnectionOptions connectionOptions;

  // A map with the number of connections currently established for each server.
  @NotNull private final Map<ObjectPair<String,Integer>,AtomicLong>
       connectionCountsByServer;

  // The post-connect processor to invoke against connections created by this
  // server set.
  @Nullable private final PostConnectProcessor postConnectProcessor;

  // The blacklist manager for this server set.
  @Nullable private final ServerSetBlacklistManager blacklistManager;

  // The socket factory to use to establish connections.
  @NotNull private final SocketFactory socketFactory;



  /**
   * Creates a new fewest connections server set with the specified set of
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
  public FewestConnectionsServerSet(@NotNull final String[] addresses,
                                    @NotNull final int[] ports)
  {
    this(addresses, ports, null, null);
  }



  /**
   * Creates a new fewest connections server set with the specified set of
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
  public FewestConnectionsServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, null, connectionOptions);
  }



  /**
   * Creates a new fewest connections server set with the specified set of
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
  public FewestConnectionsServerSet(@NotNull final String[] addresses,
                                    @NotNull final int[] ports,
                                    @Nullable final SocketFactory socketFactory)
  {
    this(addresses, ports, socketFactory, null);
  }



  /**
   * Creates a new fewest connections server set with the specified set of
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
  public FewestConnectionsServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, socketFactory, connectionOptions, null, null);
  }



  /**
   * Creates a new fewest connections server set with the specified set of
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
   *                               authenticate newly established connections.
   *                               It may be {@code null} if this server set
   *                               should not perform any authentication.
   * @param  postConnectProcessor  The post-connect processor that should be
   *                               invoked on newly established connections.  It
   *                               may be {@code null} if this server set should
   *                               not perform any post-connect processing.
   */
  public FewestConnectionsServerSet(@NotNull final String[] addresses,
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
   * Creates a new fewest connections server set with the specified set of
   * directory server addresses and port numbers.  It will use the provided
   * socket factory to create the underlying sockets.
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
   *                                       connections. It may be {@code null}
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
  public FewestConnectionsServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions,
              @Nullable final BindRequest bindRequest,
              @Nullable final PostConnectProcessor postConnectProcessor,
              final long blacklistCheckIntervalMillis)
  {
    Validator.ensureNotNull(addresses, ports);
    Validator.ensureTrue(addresses.length > 0,
         "FewestConnectionsServerSet.addresses must not be empty.");
    Validator.ensureTrue(addresses.length == ports.length,
         "FewestConnectionsServerSet addresses and ports arrays must be " +
              "the same size.");

    final LinkedHashMap<ObjectPair<String,Integer>,AtomicLong> m =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(ports.length));
    for (int i=0; i < addresses.length; i++)
    {
      m.put(new ObjectPair<>(addresses[i], ports[i]), new AtomicLong(0L));
    }

    connectionCountsByServer = Collections.unmodifiableMap(m);

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
    int i = 0;
    final String[] addresses = new String[connectionCountsByServer.size()];
    for (final ObjectPair<String,Integer> hostPort :
         connectionCountsByServer.keySet())
    {
      addresses[i++] = hostPort.getFirst();
    }

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
    int i = 0;
    final int[] ports = new int[connectionCountsByServer.size()];
    for (final ObjectPair<String,Integer> hostPort :
         connectionCountsByServer.keySet())
    {
      ports[i++] = hostPort.getSecond();
    }

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
    // Organize the servers int lists by increasing numbers of connections.
    final TreeMap<Long,List<ObjectPair<String,Integer>>> serversByCount =
         new TreeMap<>();
    for (final Map.Entry<ObjectPair<String,Integer>,AtomicLong> e :
        connectionCountsByServer.entrySet())
    {
      final ObjectPair<String,Integer> hostPort = e.getKey();
      final long count = e.getValue().get();

      List<ObjectPair<String,Integer>> l = serversByCount.get(count);
      if (l == null)
      {
        l = new ArrayList<>(connectionCountsByServer.size());
        serversByCount.put(count, l);
      }
      l.add(hostPort);
    }


    // Try the servers in order of fewest connections to most.  If there are
    // multiple servers with the same number of connections, then randomize the
    // order of servers in that list to better spread the load across all of
    // the servers.
    LDAPException lastException = null;
    List<ObjectPair<String,Integer>> blacklistedServers = null;
    for (final List<ObjectPair<String,Integer>> l : serversByCount.values())
    {
      if (l.size() > 1)
      {
        Collections.shuffle(l);
      }

      for (final ObjectPair<String,Integer> hostPort : l)
      {
        if ((blacklistManager != null) &&
             blacklistManager.isBlacklisted(hostPort))
        {
          if (blacklistedServers == null)
          {
            blacklistedServers =
                 new ArrayList<>(connectionCountsByServer.size());
          }
          blacklistedServers.add(hostPort);
          continue;
        }

        try
        {
          final LDAPConnection conn = new LDAPConnection(socketFactory,
               connectionOptions, hostPort.getFirst(), hostPort.getSecond());
          doBindPostConnectAndHealthCheckProcessing(conn, bindRequest,
               postConnectProcessor, healthCheck);
          connectionCountsByServer.get(hostPort).incrementAndGet();
          associateConnectionWithThisServerSet(conn);
          return conn;
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          lastException = le;
          if (blacklistManager != null)
          {
            blacklistManager.addToBlacklist(hostPort, healthCheck);
          }
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


    // If we've gotten here, then we've tried all servers without any success,
    // so throw the last exception that was encountered.
    throw lastException;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void handleConnectionClosed(
                      @NotNull final LDAPConnection connection,
                      @NotNull final String host, final int port,
                      @NotNull final DisconnectType disconnectType,
                      @Nullable final String message,
                      @Nullable final Throwable cause)
  {
    final ObjectPair<String,Integer> hostPort = new ObjectPair<>(host, port);
    final AtomicLong counter = connectionCountsByServer.get(hostPort);
    if (counter != null)
    {
      final long remainingCount = counter.decrementAndGet();
      if (remainingCount < 0L)
      {
        // This shouldn't happen.  If it does, reset it back to zero.
        counter.compareAndSet(remainingCount, 0L);
      }
    }
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
    buffer.append("FewestConnectionsServerSet(servers={");

    final Iterator<Map.Entry<ObjectPair<String,Integer>,AtomicLong>>
         cbsIterator = connectionCountsByServer.entrySet().iterator();
    while (cbsIterator.hasNext())
    {
      final Map.Entry<ObjectPair<String,Integer>,AtomicLong> e =
           cbsIterator.next();
      final ObjectPair<String,Integer> hostPort = e.getKey();
      final long count = e.getValue().get();

      buffer.append('\'');
      buffer.append(hostPort.getFirst());
      buffer.append(':');
      buffer.append(hostPort.getSecond());
      buffer.append("':");
      buffer.append(count);

      if (cbsIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, includesAuthentication=");
    buffer.append(bindRequest != null);
    buffer.append(", includesPostConnectProcessing=");
    buffer.append(postConnectProcessor != null);
    buffer.append(')');
  }
}
