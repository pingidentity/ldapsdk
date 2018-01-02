/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a server set implementation that will use a round-robin
 * algorithm to select the server to which the connection should be established.
 * Any number of servers may be included in this server set, and each request
 * will attempt to retrieve a connection to the next server in the list,
 * circling back to the beginning of the list as necessary.  If a server is
 * unavailable when an attempt is made to establish a connection to it, then
 * the connection will be established to the next available server in the set.
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
  // The port numbers of the target servers.
  private final int[] ports;

  // The set of connection options to use for new connections.
  private final LDAPConnectionOptions connectionOptions;

  // The socket factory to use to establish connections.
  private final SocketFactory socketFactory;

  // The addresses of the target servers.
  private final String[] addresses;

  // The slot to use for the server to be selected for the next connection
  // attempt.
  private int nextSlot;



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
  public RoundRobinServerSet(final String[] addresses, final int[] ports)
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
  public RoundRobinServerSet(final String[] addresses, final int[] ports,
                             final LDAPConnectionOptions connectionOptions)
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
  public RoundRobinServerSet(final String[] addresses, final int[] ports,
                             final SocketFactory socketFactory)
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
  public RoundRobinServerSet(final String[] addresses, final int[] ports,
                             final SocketFactory socketFactory,
                             final LDAPConnectionOptions connectionOptions)
  {
    ensureNotNull(addresses, ports);
    ensureTrue(addresses.length > 0,
               "RoundRobinServerSet.addresses must not be empty.");
    ensureTrue(addresses.length == ports.length,
               "RoundRobinServerSet addresses and ports arrays must be the " +
                    "same size.");

    this.addresses = addresses;
    this.ports     = ports;

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

    nextSlot = 0;
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
    final int initialSlotNumber = nextSlot++;

    if (nextSlot >= addresses.length)
    {
      nextSlot = 0;
    }

    try
    {
      final LDAPConnection c = new LDAPConnection(socketFactory,
           connectionOptions, addresses[initialSlotNumber],
           ports[initialSlotNumber]);
      if (healthCheck != null)
      {
        try
        {
          healthCheck.ensureNewConnectionValid(c);
        }
        catch (final LDAPException le)
        {
          c.close();
          throw le;
        }
      }
      return c;
    }
    catch (final LDAPException le)
    {
      debugException(le);
      LDAPException lastException = le;

      while (nextSlot != initialSlotNumber)
      {
        final int slotNumber = nextSlot++;
        if (nextSlot >= addresses.length)
        {
          nextSlot = 0;
        }

        try
        {
          final LDAPConnection c = new LDAPConnection(socketFactory,
               connectionOptions, addresses[slotNumber], ports[slotNumber]);
          if (healthCheck != null)
          {
            try
            {
              healthCheck.ensureNewConnectionValid(c);
            }
            catch (final LDAPException le2)
            {
              c.close();
              throw le2;
            }
          }
          return c;
        }
        catch (final LDAPException le2)
        {
          debugException(le2);
          lastException = le2;
        }
      }

      // If we've gotten here, then we've failed to connect to any of the
      // servers, so propagate the last exception to the caller.
      throw lastException;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
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

    buffer.append("})");
  }
}
