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



import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.util.Debug;



/**
 * This class provides a task that will establish a connection for use in a
 * connection pool.
 */
final class ParallelPoolConnectorTask
      implements Runnable
{
  // A reference to the first exception caught while trying to create a
  // connection.
  private final AtomicReference<LDAPException> firstException;

  // Indicates whether to throw an exception if a problem is encountered while
  // attempting to establish the connections.
  private final boolean throwOnConnectFailure;

  // The connection pool with which the connection is associated.
  private final LDAPConnectionPool pool;

  // A list to which the established connection will be added.
  private final List<LDAPConnection> connList;



  /**
   * Creates a new instance of this connector task.
   *
   * @param  pool                   The pool with which the created connection
   *                                will be established.
   * @param  connList               The list to which the established connection
   *                                will be added.  It must be threadsafe.
   * @param  firstException         A reference to the first exception caught
   *                                while attempting to establish a connection.
   * @param  throwOnConnectFailure  If an exception should be thrown if a
   *                                problem is encountered while attempting to
   *                                create the specified initial number of
   *                                connections.  If {@code true}, then the
   *                                attempt to create the pool will fail.if any
   *                                connection cannot be established.  If
   *                                {@code false}, then the pool will be created
   *                                but may have fewer than the initial number
   *                                of connections (or possibly no connections).
   */
  ParallelPoolConnectorTask(final LDAPConnectionPool pool,
                            final List<LDAPConnection> connList,
                            final AtomicReference<LDAPException> firstException,
                            final boolean throwOnConnectFailure)
  {
    this.pool                  = pool;
    this.connList              = connList;
    this.firstException        = firstException;
    this.throwOnConnectFailure = throwOnConnectFailure;
  }



  /**
   * Establishes the connection, or catches an exception while trying.
   */
  public void run()
  {
    try
    {
      if (throwOnConnectFailure && (firstException.get() != null))
      {
        return;
      }

      connList.add(pool.createConnection());
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      if (throwOnConnectFailure)
      {
        firstException.compareAndSet(null, le);
      }
    }
  }
}
