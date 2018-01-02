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



/**
 * This class provides a task that will close a connection for a connection
 * pool.
 */
final class ParallelPoolCloserTask
      implements Runnable
{
  // Indicates whether to try to send an unbind request to the server before
  // closing the connection.
  private final boolean unbind;

  // The connection to be closed.
  private final LDAPConnection connection;



  /**
   * Creates a new instance of this closer task.
   *
   * @param  connection  The connection to be closed.
   * @param  unbind       Indicates whether to try to send an unbind request to
   *                      the server before closing the connection.
   */
  ParallelPoolCloserTask(final LDAPConnection connection, final boolean unbind)
  {
    this.connection = connection;
    this.unbind     = unbind;
  }



  /**
   * Closes the connection.
   */
  public void run()
  {
    final AbstractConnectionPool pool = connection.getConnectionPool();
    if (pool != null)
    {
      final LDAPConnectionPoolStatistics stats =
           pool.getConnectionPoolStatistics();
      if (stats != null)
      {
        stats.incrementNumConnectionsClosedUnneeded();
      }
    }

    connection.setDisconnectInfo(DisconnectType.POOL_CLOSED, null, null);
    if (unbind)
    {
      connection.terminate(null);
    }
    else
    {
      connection.setClosed();
    }
  }
}
