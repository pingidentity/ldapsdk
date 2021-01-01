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



import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;



/**
 * This class provides a task that will establish a connection for use in a
 * connection pool.
 */
final class ParallelPoolConnectorTask
      implements Runnable
{
  // A reference to the first exception caught while trying to create a
  // connection.
  @NotNull private final AtomicReference<LDAPException> firstException;

  // Indicates whether to throw an exception if a problem is encountered while
  // attempting to establish the connections.
  private final boolean throwOnConnectFailure;

  // The connection pool with which the connection is associated.
  @NotNull private final LDAPConnectionPool pool;

  // A list to which the established connection will be added.
  @NotNull private final List<LDAPConnection> connList;



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
  ParallelPoolConnectorTask(@NotNull final LDAPConnectionPool pool,
       @NotNull final List<LDAPConnection> connList,
       @NotNull final AtomicReference<LDAPException> firstException,
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
  @Override()
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
