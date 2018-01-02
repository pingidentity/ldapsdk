/*
 * Copyright 2012-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2018 Ping Identity Corporation
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



import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.SocketFactory;

import com.unboundid.util.Debug;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a thread that will be used to attempt a connection to a
 * directory server in conjunction with the {@link FastestConnectServerSet}.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class FastestConnectThread
      extends Thread
{
  // The flag that will be used to indicate whether a connection has already
  // been selected by the server set.
  private final AtomicBoolean connectionSelected;

  // The queue that should be used to return the result to the server set.
  private final BlockingQueue<Object> resultQueue;

  // The port to which the connection should be established.
  private final int port;

  // The LDAP connection to be established.
  private final LDAPConnection connection;

  // The health check to use to evaluate the suitability of the established
  // connection.
  private final LDAPConnectionPoolHealthCheck healthCheck;

  // The address to which the connection should be established.
  private final String address;



  /**
   * Creates a new instance of this connect thread with the provided
   * information.
   *
   * @param  address             The address of the server to which the
   *                             connection should be established.
   * @param  port                The port of the server to which the connection
   *                             should be established.
   * @param  socketFactory       The socket factory that should be used for the
   *                             connection.
   * @param  connectionOptions   The set of connection options that should be
   *                             used for the connection.
   * @param  healthCheck         The health check to use to evaluate the
   *                             suitability of the established connection.  It
   *                             may be {@code null} if no health check is
   *                             needed.
   * @param  resultQueue         The queue that should be used to return the
   *                             result to the server set.
   * @param  connectionSelected  A flag that will be used to indicate whether a
   *                             connection has already been selected by the
   *                             associated server set.
   */
  FastestConnectThread(final String address, final int port,
                       final SocketFactory socketFactory,
                       final LDAPConnectionOptions connectionOptions,
                       final LDAPConnectionPoolHealthCheck healthCheck,
                       final BlockingQueue<Object> resultQueue,
                       final AtomicBoolean connectionSelected)
  {
    super("Fastest Connect Thread for " + address + ':' + port);
    setDaemon(true);

    this.address            = address;
    this.port               = port;
    this.healthCheck        = healthCheck;
    this.resultQueue        = resultQueue;
    this.connectionSelected = connectionSelected;

    connection = new LDAPConnection(socketFactory, connectionOptions);
  }



  /**
   * Attempts to establish the connection and return it to the server set if it
   * is acceptable.
   */
  @Override()
  public void run()
  {
    boolean returned = false;

    try
    {
      connection.connect(address, port);

      if (healthCheck != null)
      {
        healthCheck.ensureNewConnectionValid(connection);
      }

      returned = (connectionSelected.compareAndSet(false, true) &&
          resultQueue.offer(connection));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      resultQueue.offer(e);
    }
    finally
    {
      if (! returned)
      {
        connection.close();
      }
    }
  }
}
