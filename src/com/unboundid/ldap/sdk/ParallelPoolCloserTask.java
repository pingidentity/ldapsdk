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



import java.util.logging.Level;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;



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
  @NotNull private final LDAPConnection connection;



  /**
   * Creates a new instance of this closer task.
   *
   * @param  connection  The connection to be closed.
   * @param  unbind       Indicates whether to try to send an unbind request to
   *                      the server before closing the connection.
   */
  ParallelPoolCloserTask(@NotNull final LDAPConnection connection,
                         final boolean unbind)
  {
    this.connection = connection;
    this.unbind     = unbind;
  }



  /**
   * Closes the connection.
   */
  @Override()
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
        Debug.debugConnectionPool(Level.INFO, pool, connection,
             "Closing a pooled connection because the pool is closing", null);
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
