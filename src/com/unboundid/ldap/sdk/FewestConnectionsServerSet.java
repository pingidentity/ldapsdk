/*
 * Copyright 2013-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2018 Ping Identity Corporation
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
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;
import javax.net.SocketFactory;

import com.unboundid.util.NotMutable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a server set implementation that will establish a
 * connection to the server with the fewest established connections previously
 * created by the same server set instance.  If there are multiple servers that
 * share the fewest number of established connections, the first one in the list
 * will be chosen.  If a server is unavailable when an attempt is made to
 * establish a connection to it, then the connection will be established to the
 * available server with the next fewest number of established connections.
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
  // The port numbers of the target servers.
  private final int[] ports;

  // The set of connection options to use for new connections.
  private final LDAPConnectionOptions connectionOptions;

  // A list of the potentially-established connections created by this server
  // set.
  private final List<LDAPConnection> establishedConnections;

  // The socket factory to use to establish connections.
  private final SocketFactory socketFactory;

  // The addresses of the target servers.
  private final String[] addresses;



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
  public FewestConnectionsServerSet(final String[] addresses, final int[] ports)
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
  public FewestConnectionsServerSet(final String[] addresses, final int[] ports,
              final LDAPConnectionOptions connectionOptions)
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
  public FewestConnectionsServerSet(final String[] addresses, final int[] ports,
                                    final SocketFactory socketFactory)
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
  public FewestConnectionsServerSet(final String[] addresses, final int[] ports,
              final SocketFactory socketFactory,
              final LDAPConnectionOptions connectionOptions)
  {
    ensureNotNull(addresses, ports);
    ensureTrue(addresses.length > 0,
               "FewestConnectionsServerSet.addresses must not be empty.");
    ensureTrue(addresses.length == ports.length,
               "FewestConnectionsServerSet addresses and ports arrays must " +
                    "be the same size.");

    this.addresses = addresses;
    this.ports     = ports;

    establishedConnections = new ArrayList<LDAPConnection>(100);

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
  public int[] getPorts()
  {
    return ports;
  }



  /**
   * Retrieves the socket factory that will be used to establish connections.
   *
   * @return  The socket factory that will be used to establish connections.
   */
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
  public LDAPConnectionOptions getConnectionOptions()
  {
    return connectionOptions;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPConnection getConnection()
         throws LDAPException
  {
    return getConnection(null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public synchronized LDAPConnection getConnection(
                           final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    // Count the number of connections established to each server.
    final int[] counts = new int[addresses.length];
    final Iterator<LDAPConnection> iterator = establishedConnections.iterator();
    while (iterator.hasNext())
    {
      final LDAPConnection conn = iterator.next();
      if (! conn.isConnected())
      {
        iterator.remove();
        continue;
      }

      int slot = -1;
      for (int i=0; i < addresses.length; i++)
      {
        if (addresses[i].equals(conn.getConnectedAddress()) &&
            (ports[i] == conn.getConnectedPort()))
        {
          slot = i;
          break;
        }
      }

      if (slot < 0)
      {
        // This indicates a connection is established to some address:port that
        // we don't expect.  This shouldn't happen under normal circumstances.
        iterator.remove();
        break;
      }
      else
      {
        counts[slot]++;
      }
    }


    // Sort the servers based on the number of established connections.
    final TreeMap<Integer,List<ObjectPair<String,Integer>>> m =
         new TreeMap<Integer,List<ObjectPair<String,Integer>>>();
    for (int i=0; i < counts.length; i++)
    {
      final Integer count = counts[i];
      List<ObjectPair<String,Integer>> serverList = m.get(count);
      if (serverList == null)
      {
        serverList = new ArrayList<ObjectPair<String,Integer>>(counts.length);
        m.put(count, serverList);
      }
      serverList.add(new ObjectPair<String,Integer>(addresses[i], ports[i]));
    }


    // Iterate through the sorted elements, trying each server in sequence until
    // we are able to successfully establish a connection.
    LDAPException lastException = null;
    for (final List<ObjectPair<String,Integer>> l : m.values())
    {
      for (final ObjectPair<String,Integer> p : l)
      {
        try
        {
          final LDAPConnection conn = new LDAPConnection(socketFactory,
               connectionOptions, p.getFirst(), p.getSecond());
          if (healthCheck != null)
          {
            try
            {
              healthCheck.ensureNewConnectionValid(conn);
            }
            catch (final LDAPException le)
            {
              debugException(le);
              conn.close();
              throw le;
            }
          }

          establishedConnections.add(conn);
          return conn;
        }
        catch (final LDAPException le)
        {
          debugException(le);
          lastException = le;
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
  public void toString(final StringBuilder buffer)
  {
    buffer.append("FewestConnectionsServerSet(servers={");

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

    buffer.append("})");
  }
}
