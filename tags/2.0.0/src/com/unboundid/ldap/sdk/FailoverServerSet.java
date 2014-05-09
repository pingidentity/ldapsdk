/*
 * Copyright 2008-2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2010 UnboundID Corp.
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
import javax.net.SocketFactory;

import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.Validator.*;



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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FailoverServerSet
       extends ServerSet
{
  // The server sets for which we will allow failover.
  private final ServerSet[] serverSets;



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
  public FailoverServerSet(final String[] addresses, final int[] ports)
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
  public FailoverServerSet(final String[] addresses, final int[] ports,
                           final LDAPConnectionOptions connectionOptions)
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
  public FailoverServerSet(final String[] addresses, final int[] ports,
                           final SocketFactory socketFactory)
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
  public FailoverServerSet(final String[] addresses, final int[] ports,
                           final SocketFactory socketFactory,
                           final LDAPConnectionOptions connectionOptions)
  {
    ensureNotNull(addresses, ports);
    ensureTrue(addresses.length > 0,
               "FailoverServerSet.addresses must not be empty.");
    ensureTrue(addresses.length == ports.length,
         "FailoverServerSet addresses and ports arrays must be the same size.");

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
      serverSets[i] = new SingleServerSet(addresses[i], ports[i], sf, co);
    }
  }



  /**
   * Creates a new failover server set that will fail over between the provided
   * server sets.
   *
   * @param  serverSets  The server sets between which failover should occur.
   *                     It must not be {@code null} or empty.
   */
  public FailoverServerSet(final ServerSet... serverSets)
  {
    ensureNotNull(serverSets);
    ensureFalse(serverSets.length == 0,
                "FailoverServerSet.serverSets must not be empty.");

    this.serverSets = serverSets;
  }



  /**
   * Creates a new failover server set that will fail over between the provided
   * server sets.
   *
   * @param  serverSets  The server sets between which failover should occur.
   *                     It must not be {@code null} or empty.
   */
  public FailoverServerSet(final List<ServerSet> serverSets)
  {
    ensureNotNull(serverSets);
    ensureFalse(serverSets.isEmpty(),
                "FailoverServerSet.serverSets must not be empty.");

    this.serverSets = new ServerSet[serverSets.size()];
    serverSets.toArray(this.serverSets);
  }



  /**
   * Retrieves the server sets over which failover will occur.  If this failover
   * server set was created from individual servers rather than server sets,
   * then the elements contained in the returned array will be
   * {@code SingleServerSet} instances.
   *
   * @return  The server sets over which failover will occur.
   */
  public ServerSet[] getServerSets()
  {
    return serverSets;
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
  public LDAPConnection getConnection(
                             final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    LDAPException lastException = null;

    for (final ServerSet s : serverSets)
    {
      try
      {
        return s.getConnection(healthCheck);
      }
      catch (LDAPException le)
      {
        debugException(le);
        lastException = le;
      }
    }

    throw lastException;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
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
