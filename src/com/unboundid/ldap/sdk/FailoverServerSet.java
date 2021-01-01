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



import java.util.List;
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



/**
 * This class provides a server set implementation that will attempt to
 * establish connections to servers in the order they are provided.  If the
 * first server is unavailable, then it will attempt to connect to the second,
 * then to the third, etc.  Note that this implementation also makes it possible
 * to use failover between distinct server sets, which means that it will first
 * attempt to obtain a connection from the first server set and if all attempts
 * fail, it will proceed to the second set, and so on.  This can provide a
 * significant degree of flexibility in complex environments (e.g., first use a
 * round robin server set containing servers in the local data center, but if
 * none of those are available then fail over to a server set with servers in a
 * remote data center).
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for creating a failover server
 * set with information about individual servers.  It will first try to connect
 * to ds1.example.com:389, but if that fails then it will try connecting to
 * ds2.example.com:389:
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
 * FailoverServerSet failoverSet = new FailoverServerSet(addresses, ports);
 *
 * // Verify that we can establish a single connection using the server set.
 * LDAPConnection connection = failoverSet.getConnection();
 * RootDSE rootDSEFromConnection = connection.getRootDSE();
 * connection.close();
 *
 * // Verify that we can establish a connection pool using the server set.
 * SimpleBindRequest bindRequest =
 *      new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
 * LDAPConnectionPool pool =
 *      new LDAPConnectionPool(failoverSet, bindRequest, 10);
 * RootDSE rootDSEFromPool = pool.getRootDSE();
 * pool.close();
 * </PRE>
 * This second example demonstrates the process for creating a failover server
 * set which actually fails over between two different data centers (east and
 * west), with each data center containing two servers that will be accessed in
 * a round-robin manner.  It will first try to connect to one of the servers in
 * the east data center, and if that attempt fails then it will try to connect
 * to the other server in the east data center.  If both of them fail, then it
 * will try to connect to one of the servers in the west data center, and
 * finally as a last resort the other server in the west data center:
 * <PRE>
 * // Create a round-robin server set for the servers in the "east" data
 * // center.
 * String[] eastAddresses =
 * {
 *   eastServer1Address,
 *   eastServer2Address
 * };
 * int[] eastPorts =
 * {
 *   eastServer1Port,
 *   eastServer2Port
 * };
 * RoundRobinServerSet eastSet =
 *      new RoundRobinServerSet(eastAddresses, eastPorts);
 *
 * // Create a round-robin server set for the servers in the "west" data
 * // center.
 * String[] westAddresses =
 * {
 *   westServer1Address,
 *   westServer2Address
 * };
 * int[] westPorts =
 * {
 *   westServer1Port,
 *   westServer2Port
 * };
 * RoundRobinServerSet westSet =
 *      new RoundRobinServerSet(westAddresses, westPorts);
 *
 * // Create the failover server set across the east and west round-robin sets.
 * FailoverServerSet failoverSet = new FailoverServerSet(eastSet, westSet);
 *
 * // Verify that we can establish a single connection using the server set.
 * LDAPConnection connection = failoverSet.getConnection();
 * RootDSE rootDSEFromConnection = connection.getRootDSE();
 * connection.close();
 *
 * // Verify that we can establish a connection pool using the server set.
 * SimpleBindRequest bindRequest =
 *      new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
 * LDAPConnectionPool pool =
 *      new LDAPConnectionPool(failoverSet, bindRequest, 10);
 * RootDSE rootDSEFromPool = pool.getRootDSE();
 * pool.close();
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FailoverServerSet
       extends ServerSet
{
  // Indicates whether to re-order the server set list if failover occurs.
  @NotNull private final AtomicBoolean reOrderOnFailover;

  // The maximum connection age that should be set for connections established
  // using anything but the first server set.
  @Nullable private volatile Long maxFailoverConnectionAge;

  // The server sets for which we will allow failover.
  @NotNull private final ServerSet[] serverSets;



  /**
   * Creates a new failover server set with the specified set of directory
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
  public FailoverServerSet(@NotNull final String[] addresses,
                           @NotNull final int[] ports)
  {
    this(addresses, ports, null, null);
  }



  /**
   * Creates a new failover server set with the specified set of directory
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
  public FailoverServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, null, connectionOptions);
  }



  /**
   * Creates a new failover server set with the specified set of directory
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
  public FailoverServerSet(@NotNull final String[] addresses,
                           @NotNull final int[] ports,
                           @Nullable final SocketFactory socketFactory)
  {
    this(addresses, ports, socketFactory, null);
  }



  /**
   * Creates a new failover server set with the specified set of directory
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
  public FailoverServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, socketFactory, connectionOptions, null, null);
  }



  /**
   * Creates a new failover server set with the specified set of directory
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
   *                               authenticate newly-established connections.
   *                               It may be {@code null} if this server set
   *                               should not perform any authentication.
   * @param  postConnectProcessor  The post-connect processor that should be
   *                               invoked on newly-established connections.  It
   *                               may be {@code null} if this server set should
   *                               not perform any post-connect processing.
   */
  public FailoverServerSet(@NotNull final String[] addresses,
              @NotNull final int[] ports,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions,
              @Nullable final BindRequest bindRequest,
              @Nullable final PostConnectProcessor postConnectProcessor)
  {
    Validator.ensureNotNull(addresses, ports);
    Validator.ensureTrue(addresses.length > 0,
         "FailoverServerSet.addresses must not be empty.");
    Validator.ensureTrue(addresses.length == ports.length,
         "FailoverServerSet addresses and ports arrays must be the same size.");

    reOrderOnFailover = new AtomicBoolean(false);
    maxFailoverConnectionAge = null;

    final SocketFactory sf;
    if (socketFactory == null)
    {
      sf = SocketFactory.getDefault();
    }
    else
    {
      sf = socketFactory;
    }

    final LDAPConnectionOptions co;
    if (connectionOptions == null)
    {
      co = new LDAPConnectionOptions();
    }
    else
    {
      co = connectionOptions;
    }

    serverSets = new ServerSet[addresses.length];
    for (int i=0; i < serverSets.length; i++)
    {
      serverSets[i] = new SingleServerSet(addresses[i], ports[i], sf, co,
           bindRequest, postConnectProcessor);
    }
  }



  /**
   * Creates a new failover server set that will fail over between the provided
   * server sets.
   *
   * @param  serverSets  The server sets between which failover should occur.
   *                     It must not be {@code null} or empty.  All of the
   *                     provided sets must have the same return value for their
   *                     {@link #includesAuthentication()} method, and all of
   *                     the provided sets must have the same return value for
   *                     their {@link #includesPostConnectProcessing()}
   *                     method.
   */
  public FailoverServerSet(@NotNull final ServerSet... serverSets)
  {
    this(StaticUtils.toList(serverSets));
  }



  /**
   * Creates a new failover server set that will fail over between the provided
   * server sets.
   *
   * @param  serverSets  The server sets between which failover should occur.
   *                     It must not be {@code null} or empty.  All of the
   *                     provided sets must have the same return value for their
   *                     {@link #includesAuthentication()} method, and all of
   *                     the provided sets must have the same return value for
   *                     their {@link #includesPostConnectProcessing()}
   *                     method.
   */
  public FailoverServerSet(@NotNull final List<ServerSet> serverSets)
  {
    Validator.ensureNotNull(serverSets);
    Validator.ensureFalse(serverSets.isEmpty(),
         "FailoverServerSet.serverSets must not be empty.");

    this.serverSets = new ServerSet[serverSets.size()];
    serverSets.toArray(this.serverSets);

    boolean anySupportsAuthentication = false;
    boolean allSupportAuthentication = true;
    boolean anySupportsPostConnectProcessing = false;
    boolean allSupportPostConnectProcessing = true;
    for (final ServerSet serverSet : this.serverSets)
    {
      if (serverSet.includesAuthentication())
      {
        anySupportsAuthentication = true;
      }
      else
      {
        allSupportAuthentication = false;
      }

      if (serverSet.includesPostConnectProcessing())
      {
        anySupportsPostConnectProcessing = true;
      }
      else
      {
        allSupportPostConnectProcessing = false;
      }
    }

    if (anySupportsAuthentication)
    {
      Validator.ensureTrue(allSupportAuthentication,
           "When creating a FailoverServerSet from a collection of server " +
                "sets, either all of those sets must include authentication, " +
                "or none of those sets may include authentication.");
    }

    if (anySupportsPostConnectProcessing)
    {
      Validator.ensureTrue(allSupportPostConnectProcessing,
           "When creating a FailoverServerSet from a collection of server " +
                "sets, either all of those sets must include post-connect " +
                "processing, or none of those sets may include post-connect " +
                "processing.");
    }

    reOrderOnFailover = new AtomicBoolean(false);
    maxFailoverConnectionAge = null;
  }



  /**
   * Retrieves the server sets over which failover will occur.  If this failover
   * server set was created from individual servers rather than server sets,
   * then the elements contained in the returned array will be
   * {@code SingleServerSet} instances.
   *
   * @return  The server sets over which failover will occur.
   */
  @NotNull()
  public ServerSet[] getServerSets()
  {
    return serverSets;
  }



  /**
   * Indicates whether the list of servers or server sets used by this failover
   * server set should be re-ordered in the event that a failure is encountered
   * while attempting to establish a connection.  If {@code true}, then any
   * failed attempt to establish a connection to a server set at the beginning
   * of the list may cause that server/set to be moved to the end of the list so
   * that it will be the last one tried on the next attempt.
   *
   * @return  {@code true} if the order of elements in the associated list of
   *          servers or server sets should be updated if a failure occurs while
   *          attempting to establish a connection, or {@code false} if the
   *          original order should be preserved.
   */
  public boolean reOrderOnFailover()
  {
    return reOrderOnFailover.get();
  }



  /**
   * Specifies whether the list of servers or server sets used by this failover
   * server set should be re-ordered in the event that a failure is encountered
   * while attempting to establish a connection.  By default, the original
   * order will be preserved, but if this method is called with a value of
   * {@code true}, then a failed attempt to establish a connection to the server
   * or server set at the beginning of the list may cause that server to be
   * moved to the end of the list so that it will be the last server/set tried
   * on the next attempt.
   *
   * @param  reOrderOnFailover  Indicates whether the list of servers or server
   *                            sets should be re-ordered in the event that a
   *                            failure is encountered while attempting to
   *                            establish a connection.
   */
  public void setReOrderOnFailover(final boolean reOrderOnFailover)
  {
    this.reOrderOnFailover.set(reOrderOnFailover);
  }



  /**
   * Retrieves the maximum connection age that should be used for "failover"
   * connections (i.e., connections that are established to any server other
   * than the most-preferred server, or established using any server set other
   * than the most-preferred set).  This will only be used if this failover
   * server set is used to create an {@link LDAPConnectionPool}, for connections
   * within that pool.
   *
   * @return  The maximum connection age that should be used for failover
   *          connections, a value of zero to indicate that no maximum age
   *          should apply to those connections, or {@code null} if the maximum
   *          connection age should be determined by the associated connection
   *          pool.
   */
  @Nullable()
  public Long getMaxFailoverConnectionAgeMillis()
  {
    return maxFailoverConnectionAge;
  }



  /**
   * Specifies the maximum connection age that should be used for "failover"
   * connections (i.e., connections that are established to any server other
   * than the most-preferred server, or established using any server set other
   * than the most-preferred set).  This will only be used if this failover
   * server set is used to create an {@link LDAPConnectionPool}, for connections
   * within that pool.
   *
   * @param  maxFailoverConnectionAge  The maximum connection age that should be
   *                                   used for failover connections.  It may be
   *                                   less than or equal to zero to indicate
   *                                   that no maximum age should apply to such
   *                                   connections, or {@code null} to indicate
   *                                   that the maximum connection age should be
   *                                   determined by the associated connection
   *                                   pool.
   */
  public void setMaxFailoverConnectionAgeMillis(
                   @Nullable final Long maxFailoverConnectionAge)
  {
    if (maxFailoverConnectionAge == null)
    {
      this.maxFailoverConnectionAge = null;
    }
    else if (maxFailoverConnectionAge > 0L)
    {
      this.maxFailoverConnectionAge = maxFailoverConnectionAge;
    }
    else
    {
      this.maxFailoverConnectionAge = 0L;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean includesAuthentication()
  {
    return serverSets[0].includesAuthentication();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean includesPostConnectProcessing()
  {
    return serverSets[0].includesPostConnectProcessing();
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
    // NOTE:  This method does not associate the connection that is created with
    // this server set.  This is because another server set is actually used to
    // create the connection, and we want that server set to be able to
    // associate itself with the connection.  The failover server set does not
    // override the handleConnectionClosed method, but other server sets might,
    // and associating a connection with the failover server set instead of the
    // downstream set that actually created it could prevent that downstream
    // set from being properly notified about the connection closure.

    if (reOrderOnFailover.get() && (serverSets.length > 1))
    {
      synchronized (this)
      {
        // First, try to get a connection using the first set in the list.  If
        // this succeeds, then we don't need to go any further.
        try
        {
          return serverSets[0].getConnection(healthCheck);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
        }

        // If we've gotten here, then we will need to re-order the list unless
        // all other attempts fail.
        int successfulPos = -1;
        LDAPConnection conn = null;
        LDAPException lastException = null;
        for (int i=1; i < serverSets.length; i++)
        {
          try
          {
            conn = serverSets[i].getConnection(healthCheck);
            successfulPos = i;
            break;
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            lastException = le;
          }
        }

        if (successfulPos > 0)
        {
          int pos = 0;
          final ServerSet[] setCopy = new ServerSet[serverSets.length];
          for (int i=successfulPos; i < serverSets.length; i++)
          {
            setCopy[pos++] = serverSets[i];
          }

          for (int i=0; i < successfulPos; i++)
          {
            setCopy[pos++] = serverSets[i];
          }

          System.arraycopy(setCopy, 0, serverSets, 0, setCopy.length);
          if (maxFailoverConnectionAge != null)
          {
            conn.setAttachment(
                 LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE,
                 maxFailoverConnectionAge);
          }
          return conn;
        }
        else
        {
          throw lastException;
        }
      }
    }
    else
    {
      LDAPException lastException = null;

      boolean first = true;
      for (final ServerSet s : serverSets)
      {
        try
        {
          final LDAPConnection conn = s.getConnection(healthCheck);
          if ((! first) && (maxFailoverConnectionAge != null))
          {
            conn.setAttachment(
                 LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE,
                 maxFailoverConnectionAge);
          }
          return conn;
        }
        catch (final LDAPException le)
        {
          first = false;
          Debug.debugException(le);
          lastException = le;
        }
      }

      throw lastException;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("FailoverServerSet(serverSets={");

    for (int i=0; i < serverSets.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      serverSets[i].toString(buffer);
    }

    buffer.append("})");
  }
}
