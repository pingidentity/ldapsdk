/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;

import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides an implementation of an LDAP connection pool which
 * maintains a dedicated connection for each thread using the connection pool.
 * Connections will be created on an on-demand basis, so that if a thread
 * attempts to use this connection pool for the first time then a new connection
 * will be created by that thread.  This implementation eliminates the need to
 * determine how best to size the connection pool, and it can eliminate
 * contention among threads when trying to access a shared set of connections.
 * All connections will be properly closed when the connection pool itself is
 * closed, but if any thread which had previously used the connection pool stops
 * running before the connection pool is closed, then the connection associated
 * with that thread will also be closed by the Java finalizer.
 * <BR><BR>
 * If a thread obtains a connection to this connection pool, then that
 * connection should not be made available to any other thread.  Similarly, if
 * a thread attempts to check out multiple connections from the pool, then the
 * same connection instance will be returned each time.
 * <BR><BR>
 * The capabilities offered by this class are generally the same as those
 * provided by the {@link LDAPConnectionPool} class, as is the manner in which
 * applications should interact with it.  See the class-level documentation for
 * the {@code LDAPConnectionPool} class for additional information and examples.
 * <BR><BR>
 * One difference between this connection pool implementation and that provided
 * by the {@link LDAPConnectionPool} class is that this implementation does not
 * currently support periodic background health checks.  You can define health
 * checks that will be invoked when a new connection is created, just before it
 * is checked out for use, just after it is released, and if an error occurs
 * while using the connection, but it will not maintain a separate background
 * thread
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPThreadLocalConnectionPool
       extends AbstractConnectionPool
{
  /**
   * The default health check interval for this connection pool, which is set to
   * 60000 milliseconds (60 seconds).
   */
  private static final long DEFAULT_HEALTH_CHECK_INTERVAL = 60_000L;



  // The types of operations that should be retried if they fail in a manner
  // that may be the result of a connection that is no longer valid.
  @NotNull private final AtomicReference<Set<OperationType>>
       retryOperationTypes;

  // Indicates whether this connection pool has been closed.
  private volatile boolean closed;

  // The bind request to use to perform authentication whenever a new connection
  // is established.
  @Nullable private volatile BindRequest bindRequest;

  // The map of connections maintained for this connection pool.
  @NotNull private final ConcurrentHashMap<Thread,LDAPConnection> connections;

  // The health check implementation that should be used for this connection
  // pool.
  @NotNull private LDAPConnectionPoolHealthCheck healthCheck;

  // The thread that will be used to perform periodic background health checks
  // for this connection pool.
  @NotNull private final LDAPConnectionPoolHealthCheckThread healthCheckThread;

  // The statistics for this connection pool.
  @NotNull private final LDAPConnectionPoolStatistics poolStatistics;

  // The length of time in milliseconds between periodic health checks against
  // the available connections in this pool.
  private volatile long healthCheckInterval;

  // The time that the last expired connection was closed.
  private volatile long lastExpiredDisconnectTime;

  // The maximum length of time in milliseconds that a connection should be
  // allowed to be established before terminating and re-establishing the
  // connection.
  private volatile long maxConnectionAge;

  // The minimum length of time in milliseconds that must pass between
  // disconnects of connections that have exceeded the maximum connection age.
  private volatile long minDisconnectInterval;

  // The schema that should be shared for connections in this pool, along with
  // its expiration time.
  @Nullable private volatile ObjectPair<Long,Schema> pooledSchema;

  // The post-connect processor for this connection pool, if any.
  @Nullable private final PostConnectProcessor postConnectProcessor;

  // The server set to use for establishing connections for use by this pool.
  @NotNull private volatile ServerSet serverSet;

  // The user-friendly name assigned to this connection pool.
  @Nullable private String connectionPoolName;



  /**
   * Creates a new LDAP thread-local connection pool in which all connections
   * will be clones of the provided connection.
   *
   * @param  connection  The connection to use to provide the template for the
   *                     other connections to be created.  This connection will
   *                     be included in the pool.  It must not be {@code null},
   *                     and it must be established to the target server.  It
   *                     does not necessarily need to be authenticated if all
   *                     connections in the pool are to be unauthenticated.
   *
   * @throws  LDAPException  If the provided connection cannot be used to
   *                         initialize the pool.  If this is thrown, then all
   *                         connections associated with the pool (including the
   *                         one provided as an argument) will be closed.
   */
  public LDAPThreadLocalConnectionPool(@NotNull final LDAPConnection connection)
         throws LDAPException
  {
    this(connection, null);
  }



  /**
   * Creates a new LDAP thread-local connection pool in which all connections
   * will be clones of the provided connection.
   *
   * @param  connection            The connection to use to provide the template
   *                               for the other connections to be created.
   *                               This connection will be included in the pool.
   *                               It must not be {@code null}, and it must be
   *                               established to the target server.  It does
   *                               not necessarily need to be authenticated if
   *                               all connections in the pool are to be
   *                               unauthenticated.
   * @param  postConnectProcessor  A processor that should be used to perform
   *                               any post-connect processing for connections
   *                               in this pool.  It may be {@code null} if no
   *                               special processing is needed.  Note that this
   *                               processing will not be invoked on the
   *                               provided connection that will be used as the
   *                               first connection in the pool.
   *
   * @throws  LDAPException  If the provided connection cannot be used to
   *                         initialize the pool.  If this is thrown, then all
   *                         connections associated with the pool (including the
   *                         one provided as an argument) will be closed.
   */
  public LDAPThreadLocalConnectionPool(
              @NotNull final LDAPConnection connection,
              @Nullable final PostConnectProcessor postConnectProcessor)
         throws LDAPException
  {
    Validator.ensureNotNull(connection);

    // NOTE:  The post-connect processor (if any) will be used in the server
    // set that we create rather than in the connection pool itself.
    this.postConnectProcessor = null;

    healthCheck               = new LDAPConnectionPoolHealthCheck();
    healthCheckInterval       = DEFAULT_HEALTH_CHECK_INTERVAL;
    poolStatistics            = new LDAPConnectionPoolStatistics(this);
    connectionPoolName        = null;
    retryOperationTypes       = new AtomicReference<>(
         Collections.unmodifiableSet(EnumSet.noneOf(OperationType.class)));

    if (! connection.isConnected())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
                              ERR_POOL_CONN_NOT_ESTABLISHED.get());
    }


    bindRequest = connection.getLastBindRequest();
    serverSet = new SingleServerSet(connection.getConnectedAddress(),
                                    connection.getConnectedPort(),
                                    connection.getLastUsedSocketFactory(),
                                    connection.getConnectionOptions(), null,
                                    postConnectProcessor);

    connections = new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(20));
    connections.put(Thread.currentThread(), connection);

    lastExpiredDisconnectTime = 0L;
    maxConnectionAge          = 0L;
    closed                    = false;
    minDisconnectInterval     = 0L;

    healthCheckThread = new LDAPConnectionPoolHealthCheckThread(this);
    healthCheckThread.start();

    final LDAPConnectionOptions opts = connection.getConnectionOptions();
    if (opts.usePooledSchema())
    {
      try
      {
        final Schema schema = connection.getSchema();
        if (schema != null)
        {
          connection.setCachedSchema(schema);

          final long currentTime = System.currentTimeMillis();
          final long timeout = opts.getPooledSchemaTimeoutMillis();
          if ((timeout <= 0L) || (timeout+currentTime <= 0L))
          {
            pooledSchema = new ObjectPair<>(Long.MAX_VALUE, schema);
          }
          else
          {
            pooledSchema = new ObjectPair<>(timeout+currentTime, schema);
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Creates a new LDAP thread-local connection pool which will use the provided
   * server set and bind request for creating new connections.
   *
   * @param  serverSet       The server set to use to create the connections.
   *                         It is acceptable for the server set to create the
   *                         connections across multiple servers.
   * @param  bindRequest     The bind request to use to authenticate the
   *                         connections that are established.  It may be
   *                         {@code null} if no authentication should be
   *                         performed on the connections.  Note that if the
   *                         server set is configured to perform
   *                         authentication, this bind request should be the
   *                         same bind request used by the server set.  This
   *                         is important because even though the server set
   *                         may be used to perform the initial authentication
   *                         on a newly established connection, this connection
   *                         pool may still need to re-authenticate the
   *                         connection.
   */
  public LDAPThreadLocalConnectionPool(@NotNull final ServerSet serverSet,
                                       @Nullable final BindRequest bindRequest)
  {
    this(serverSet, bindRequest, null);
  }



  /**
   * Creates a new LDAP thread-local connection pool which will use the provided
   * server set and bind request for creating new connections.
   *
   * @param  serverSet             The server set to use to create the
   *                               connections.  It is acceptable for the server
   *                               set to create the connections across multiple
   *                               servers.
   * @param  bindRequest           The bind request to use to authenticate the
   *                               connections that are established.  It may be
   *                               {@code null} if no authentication should be
   *                               performed on the connections.  Note that if
   *                               the server set is configured to perform
   *                               authentication, this bind request should be
   *                               the same bind request used by the server set.
   *                               This is important because even though the
   *                               server set may be used to perform the
   *                               initial authentication on a newly
   *                               established connection, this connection
   *                               pool may still need to re-authenticate the
   *                               connection.
   * @param  postConnectProcessor  A processor that should be used to perform
   *                               any post-connect processing for connections
   *                               in this pool.  It may be {@code null} if no
   *                               special processing is needed.  Note that if
   *                               the server set is configured with a
   *                               non-{@code null} post-connect processor, then
   *                               the post-connect processor provided to the
   *                               pool must be {@code null}.
   */
  public LDAPThreadLocalConnectionPool(@NotNull final ServerSet serverSet,
              @Nullable final BindRequest bindRequest,
              @Nullable final PostConnectProcessor postConnectProcessor)
  {
    Validator.ensureNotNull(serverSet);

    this.serverSet            = serverSet;
    this.bindRequest          = bindRequest;
    this.postConnectProcessor = postConnectProcessor;

    if (serverSet.includesAuthentication())
    {
      Validator.ensureTrue((bindRequest != null),
           "LDAPThreadLocalConnectionPool.bindRequest must not be null if " +
                "serverSet.includesAuthentication returns true");
    }

    if (serverSet.includesPostConnectProcessing())
    {
      Validator.ensureTrue((postConnectProcessor == null),
           "LDAPThreadLocalConnectionPool.postConnectProcessor must be null " +
                "if serverSet.includesPostConnectProcessing returns true.");
    }

    healthCheck               = new LDAPConnectionPoolHealthCheck();
    healthCheckInterval       = DEFAULT_HEALTH_CHECK_INTERVAL;
    poolStatistics            = new LDAPConnectionPoolStatistics(this);
    connectionPoolName        = null;
    retryOperationTypes       = new AtomicReference<>(
         Collections.unmodifiableSet(EnumSet.noneOf(OperationType.class)));

    connections = new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(20));

    lastExpiredDisconnectTime = 0L;
    maxConnectionAge          = 0L;
    minDisconnectInterval     = 0L;
    closed                    = false;

    healthCheckThread = new LDAPConnectionPoolHealthCheckThread(this);
    healthCheckThread.start();
  }



  /**
   * Creates a new LDAP connection for use in this pool.
   *
   * @return  A new connection created for use in this pool.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         the connection.  If a connection had been created,
   *                         it will be closed.
   */
  @SuppressWarnings("deprecation")
  @NotNull()
  private LDAPConnection createConnection()
          throws LDAPException
  {
    final LDAPConnection c;
    try
    {
      c = serverSet.getConnection(healthCheck);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      poolStatistics.incrementNumFailedConnectionAttempts();
      Debug.debugConnectionPool(Level.SEVERE, this, null,
           "Unable to create a new pooled connection", le);
      throw le;
    }
    c.setConnectionPool(this);


    // Auto-reconnect must be disabled for pooled connections, so turn it off
    // if the associated connection options have it enabled for some reason.
    LDAPConnectionOptions opts = c.getConnectionOptions();
    if (opts.autoReconnect())
    {
      opts = opts.duplicate();
      opts.setAutoReconnect(false);
      c.setConnectionOptions(opts);
    }


    // Invoke pre-authentication post-connect processing.
    if (postConnectProcessor != null)
    {
      try
      {
        postConnectProcessor.processPreAuthenticatedConnection(c);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        try
        {
          poolStatistics.incrementNumFailedConnectionAttempts();
          Debug.debugConnectionPool(Level.SEVERE, this, c,
               "Exception in pre-authentication post-connect processing", e);
          c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null, e);
          c.setClosed();
        }
        catch (final Exception e2)
        {
          Debug.debugException(e2);
        }

        if (e instanceof LDAPException)
        {
          throw ((LDAPException) e);
        }
        else
        {
          throw new LDAPException(ResultCode.CONNECT_ERROR,
               ERR_POOL_POST_CONNECT_ERROR.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }
    }


    // Authenticate the connection if appropriate.
    if ((bindRequest != null) && (! serverSet.includesAuthentication()))
    {
      BindResult bindResult;
      try
      {
        bindResult = c.bind(bindRequest.duplicate());
      }
      catch (final LDAPBindException lbe)
      {
        Debug.debugException(lbe);
        bindResult = lbe.getBindResult();
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        bindResult = new BindResult(le);
      }

      try
      {
        healthCheck.ensureConnectionValidAfterAuthentication(c, bindResult);
        if (bindResult.getResultCode() != ResultCode.SUCCESS)
        {
          throw new LDAPBindException(bindResult);
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        try
        {
          poolStatistics.incrementNumFailedConnectionAttempts();
          if (bindResult.getResultCode() != ResultCode.SUCCESS)
          {
            Debug.debugConnectionPool(Level.SEVERE, this, c,
                 "Failed to authenticate a new pooled connection", le);
          }
          else
          {
            Debug.debugConnectionPool(Level.SEVERE, this, c,
                 "A new pooled connection failed its post-authentication " +
                      "health check",
                 le);
          }
          c.setDisconnectInfo(DisconnectType.BIND_FAILED, null, le);
          c.setClosed();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }

        throw le;
      }
    }


    // Invoke post-authentication post-connect processing.
    if (postConnectProcessor != null)
    {
      try
      {
        postConnectProcessor.processPostAuthenticatedConnection(c);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        try
        {
          poolStatistics.incrementNumFailedConnectionAttempts();
          Debug.debugConnectionPool(Level.SEVERE, this, c,
               "Exception in post-authentication post-connect processing", e);
          c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null, e);
          c.setClosed();
        }
        catch (final Exception e2)
        {
          Debug.debugException(e2);
        }

        if (e instanceof LDAPException)
        {
          throw ((LDAPException) e);
        }
        else
        {
          throw new LDAPException(ResultCode.CONNECT_ERROR,
               ERR_POOL_POST_CONNECT_ERROR.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }
    }


    // Get the pooled schema if appropriate.
    if (opts.usePooledSchema())
    {
      final long currentTime = System.currentTimeMillis();
      if ((pooledSchema == null) || (currentTime > pooledSchema.getFirst()))
      {
        try
        {
          final Schema schema = c.getSchema();
          if (schema != null)
          {
            c.setCachedSchema(schema);

            final long timeout = opts.getPooledSchemaTimeoutMillis();
            if ((timeout <= 0L) || (currentTime + timeout <= 0L))
            {
              pooledSchema = new ObjectPair<>(Long.MAX_VALUE, schema);
            }
            else
            {
              pooledSchema = new ObjectPair<>((currentTime+timeout), schema);
            }
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);

          // There was a problem retrieving the schema from the server, but if
          // we have an earlier copy then we can assume it's still valid.
          if (pooledSchema != null)
          {
            c.setCachedSchema(pooledSchema.getSecond());
          }
        }
      }
      else
      {
        c.setCachedSchema(pooledSchema.getSecond());
      }
    }


    // Finish setting up the connection.
    c.setConnectionPoolName(connectionPoolName);
    poolStatistics.incrementNumSuccessfulConnectionAttempts();
    Debug.debugConnectionPool(Level.INFO, this, c,
         "Successfully created a new pooled connection", null);

    return c;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void close()
  {
    close(true, 1);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void close(final boolean unbind, final int numThreads)
  {
    try
    {
      final boolean healthCheckThreadAlreadySignaled = closed;
      closed = true;
      healthCheckThread.stopRunning(! healthCheckThreadAlreadySignaled);

      try
      {
        serverSet.shutDown();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      if (numThreads > 1)
      {
        final ArrayList<LDAPConnection> connList =
             new ArrayList<>(connections.size());
        final Iterator<LDAPConnection> iterator =
             connections.values().iterator();
        while (iterator.hasNext())
        {
          connList.add(iterator.next());
          iterator.remove();
        }

        if (! connList.isEmpty())
        {
          final ParallelPoolCloser closer =
               new ParallelPoolCloser(connList, unbind, numThreads);
          closer.closeConnections();
        }
      }
      else
      {
        final Iterator<Map.Entry<Thread,LDAPConnection>> iterator =
             connections.entrySet().iterator();
        while (iterator.hasNext())
        {
          final LDAPConnection conn = iterator.next().getValue();
          iterator.remove();

          poolStatistics.incrementNumConnectionsClosedUnneeded();
          Debug.debugConnectionPool(Level.INFO, this, conn,
               "Closed a connection as part of closing the connection pool",
               null);
          conn.setDisconnectInfo(DisconnectType.POOL_CLOSED, null, null);
          if (unbind)
          {
            conn.terminate(null);
          }
          else
          {
            conn.setClosed();
          }
        }
      }
    }
    finally
    {
      Debug.debugConnectionPool(Level.INFO, this, null,
           "Closed the connection pool", null);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean isClosed()
  {
    return closed;
  }



  /**
   * Processes a simple bind using a connection from this connection pool, and
   * then reverts that authentication by re-binding as the same user used to
   * authenticate new connections.  If new connections are unauthenticated, then
   * the subsequent bind will be an anonymous simple bind.  This method attempts
   * to ensure that processing the provided bind operation does not have a
   * lasting impact the authentication state of the connection used to process
   * it.
   * <BR><BR>
   * If the second bind attempt (the one used to restore the authentication
   * identity) fails, the connection will be closed as defunct so that a new
   * connection will be created to take its place.
   *
   * @param  bindDN    The bind DN for the simple bind request.
   * @param  password  The password for the simple bind request.
   * @param  controls  The optional set of controls for the simple bind request.
   *
   * @return  The result of processing the provided bind operation.
   *
   * @throws  LDAPException  If the server rejects the bind request, or if a
   *                         problem occurs while sending the request or reading
   *                         the response.
   */
  @NotNull()
  public BindResult bindAndRevertAuthentication(@Nullable final String bindDN,
                         @Nullable final String password,
                         @Nullable final Control... controls)
         throws LDAPException
  {
    return bindAndRevertAuthentication(
         new SimpleBindRequest(bindDN, password, controls));
  }



  /**
   * Processes the provided bind request using a connection from this connection
   * pool, and then reverts that authentication by re-binding as the same user
   * used to authenticate new connections.  If new connections are
   * unauthenticated, then the subsequent bind will be an anonymous simple bind.
   * This method attempts to ensure that processing the provided bind operation
   * does not have a lasting impact the authentication state of the connection
   * used to process it.
   * <BR><BR>
   * If the second bind attempt (the one used to restore the authentication
   * identity) fails, the connection will be closed as defunct so that a new
   * connection will be created to take its place.
   *
   * @param  bindRequest  The bind request to be processed.  It must not be
   *                      {@code null}.
   *
   * @return  The result of processing the provided bind operation.
   *
   * @throws  LDAPException  If the server rejects the bind request, or if a
   *                         problem occurs while sending the request or reading
   *                         the response.
   */
  @NotNull()
  public BindResult bindAndRevertAuthentication(
                         @NotNull final BindRequest bindRequest)
         throws LDAPException
  {
    LDAPConnection conn = getConnection();

    try
    {
      final BindResult result = conn.bind(bindRequest);
      releaseAndReAuthenticateConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      Debug.debugException(t);

      if (t instanceof LDAPException)
      {
        final LDAPException le = (LDAPException) t;

        boolean shouldThrow;
        try
        {
          healthCheck.ensureConnectionValidAfterException(conn, le);

          // The above call will throw an exception if the connection doesn't
          // seem to be valid, so if we've gotten here then we should assume
          // that it is valid and we will pass the exception onto the client
          // without retrying the operation.
          releaseAndReAuthenticateConnection(conn);
          shouldThrow = true;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);

          // This implies that the connection is not valid.  If the pool is
          // configured to re-try bind operations on a newly-established
          // connection, then that will be done later in this method.
          // Otherwise, release the connection as defunct and pass the bind
          // exception onto the client.
          if (! getOperationTypesToRetryDueToInvalidConnections().contains(
                     OperationType.BIND))
          {
            releaseDefunctConnection(conn);
            shouldThrow = true;
          }
          else
          {
            shouldThrow = false;
          }
        }

        if (shouldThrow)
        {
          throw le;
        }
      }
      else
      {
        releaseDefunctConnection(conn);
        StaticUtils.rethrowIfError(t);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_POOL_OP_EXCEPTION.get(StaticUtils.getExceptionMessage(t)), t);
      }
    }


    // If we've gotten here, then the bind operation should be re-tried on a
    // newly-established connection.
    conn = replaceDefunctConnection(conn);

    try
    {
      final BindResult result = conn.bind(bindRequest);
      releaseAndReAuthenticateConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      Debug.debugException(t);

      if (t instanceof LDAPException)
      {
        final LDAPException le = (LDAPException) t;

        try
        {
          healthCheck.ensureConnectionValidAfterException(conn, le);
          releaseAndReAuthenticateConnection(conn);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          releaseDefunctConnection(conn);
        }

        throw le;
      }
      else
      {
        releaseDefunctConnection(conn);
        StaticUtils.rethrowIfError(t);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_POOL_OP_EXCEPTION.get(StaticUtils.getExceptionMessage(t)), t);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnection getConnection()
         throws LDAPException
  {
    final Thread t = Thread.currentThread();
    LDAPConnection conn = connections.get(t);

    if (closed)
    {
      if (conn != null)
      {
        conn.terminate(null);
        connections.remove(t);
      }

      poolStatistics.incrementNumFailedCheckouts();
      Debug.debugConnectionPool(Level.SEVERE, this, null,
           "Failed to get a connection to a closed connection pool", null);
      throw new LDAPException(ResultCode.CONNECT_ERROR,
                              ERR_POOL_CLOSED.get());
    }

    boolean created = false;
    if ((conn == null) || (! conn.isConnected()))
    {
      conn = createConnection();
      connections.put(t, conn);
      created = true;
    }

    try
    {
      healthCheck.ensureConnectionValidForCheckout(conn);
      if (created)
      {
        poolStatistics.incrementNumSuccessfulCheckoutsNewConnection();
        Debug.debugConnectionPool(Level.INFO, this, conn,
             "Checked out a newly created pooled connection", null);
      }
      else
      {
        poolStatistics.incrementNumSuccessfulCheckoutsWithoutWaiting();
        Debug.debugConnectionPool(Level.INFO, this, conn,
             "Checked out an existing pooled connection", null);
      }
      return conn;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      conn.setClosed();
      connections.remove(t);

      if (created)
      {
        poolStatistics.incrementNumFailedCheckouts();
        Debug.debugConnectionPool(Level.SEVERE, this, conn,
             "Failed to check out a connection because a newly created " +
                  "connection failed the checkout health check",
             le);
        throw le;
      }
    }

    try
    {
      conn = createConnection();
      healthCheck.ensureConnectionValidForCheckout(conn);
      connections.put(t, conn);
      poolStatistics.incrementNumSuccessfulCheckoutsNewConnection();
      Debug.debugConnectionPool(Level.INFO, this, conn,
           "Checked out a newly created pooled connection", null);
      return conn;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      poolStatistics.incrementNumFailedCheckouts();
      if (conn == null)
      {
        Debug.debugConnectionPool(Level.SEVERE, this, conn,
             "Unable to check out a connection because an error occurred " +
                  "while establishing the connection",
             le);
      }
      else
      {
        Debug.debugConnectionPool(Level.SEVERE, this, conn,
             "Unable to check out a newly created connection because it " +
                  "failed the checkout health check",
             le);
        conn.setClosed();
      }

      throw le;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void releaseConnection(@NotNull final LDAPConnection connection)
  {
    if (connection == null)
    {
      return;
    }

    connection.setConnectionPoolName(connectionPoolName);
    if (connectionIsExpired(connection))
    {
      try
      {
        final LDAPConnection newConnection = createConnection();
        connections.put(Thread.currentThread(), newConnection);

        connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_EXPIRED,
             null, null);
        connection.terminate(null);
        poolStatistics.incrementNumConnectionsClosedExpired();
        Debug.debugConnectionPool(Level.WARNING, this, connection,
             "Closing a released connection because it is expired", null);
        lastExpiredDisconnectTime = System.currentTimeMillis();
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
      }
    }

    try
    {
      healthCheck.ensureConnectionValidForRelease(connection);
    }
    catch (final LDAPException le)
    {
      releaseDefunctConnection(connection);
      return;
    }

    poolStatistics.incrementNumReleasedValid();
    Debug.debugConnectionPool(Level.INFO, this, connection,
         "Released a connection back to the pool", null);

    if (closed)
    {
      close();
    }
  }



  /**
   * Performs a bind on the provided connection before releasing it back to the
   * pool, so that it will be authenticated as the same user as
   * newly-established connections.  If newly-established connections are
   * unauthenticated, then this method will perform an anonymous simple bind to
   * ensure that the resulting connection is unauthenticated.
   *
   * Releases the provided connection back to this pool.
   *
   * @param  connection  The connection to be released back to the pool after
   *                     being re-authenticated.
   */
  public void releaseAndReAuthenticateConnection(
                   @NotNull final LDAPConnection connection)
  {
    if (connection == null)
    {
      return;
    }

    try
    {
      BindResult bindResult;
      try
      {
        if (bindRequest == null)
        {
          bindResult = connection.bind("", "");
        }
        else
        {
          bindResult = connection.bind(bindRequest.duplicate());
        }
      }
      catch (final LDAPBindException lbe)
      {
        Debug.debugException(lbe);
        bindResult = lbe.getBindResult();
      }

      try
      {
        healthCheck.ensureConnectionValidAfterAuthentication(connection,
             bindResult);
        if (bindResult.getResultCode() != ResultCode.SUCCESS)
        {
          throw new LDAPBindException(bindResult);
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        try
        {
          connection.setDisconnectInfo(DisconnectType.BIND_FAILED, null, le);
          connection.terminate(null);
          releaseDefunctConnection(connection);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }

        throw le;
      }

      releaseConnection(connection);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      releaseDefunctConnection(connection);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void releaseDefunctConnection(@NotNull final LDAPConnection connection)
  {
    if (connection == null)
    {
      return;
    }

    connection.setConnectionPoolName(connectionPoolName);
    poolStatistics.incrementNumConnectionsClosedDefunct();
    Debug.debugConnectionPool(Level.WARNING, this, connection,
         "Releasing a defunct connection", null);
    handleDefunctConnection(connection);
  }



  /**
   * Performs the real work of terminating a defunct connection and replacing it
   * with a new connection if possible.
   *
   * @param  connection  The defunct connection to be replaced.
   */
  private void handleDefunctConnection(@NotNull final LDAPConnection connection)
  {
    final Thread t = Thread.currentThread();

    connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, null,
                                 null);
    connection.setClosed();
    connections.remove(t);

    if (closed)
    {
      return;
    }

    try
    {
      final LDAPConnection conn = createConnection();
      connections.put(t, conn);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnection replaceDefunctConnection(
                             @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    poolStatistics.incrementNumConnectionsClosedDefunct();
    Debug.debugConnectionPool(Level.WARNING, this, connection,
         "Releasing a defunct connection that is to be replaced", null);
    connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, null,
                                 null);
    connection.setClosed();
    connections.remove(Thread.currentThread(), connection);

    if (closed)
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR, ERR_POOL_CLOSED.get());
    }

    final LDAPConnection newConnection = createConnection();
    connections.put(Thread.currentThread(), newConnection);
    return newConnection;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Set<OperationType> getOperationTypesToRetryDueToInvalidConnections()
  {
    return retryOperationTypes.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setRetryFailedOperationsDueToInvalidConnections(
                   @Nullable final Set<OperationType> operationTypes)
  {
    if ((operationTypes == null) || operationTypes.isEmpty())
    {
      retryOperationTypes.set(
           Collections.unmodifiableSet(EnumSet.noneOf(OperationType.class)));
    }
    else
    {
      final EnumSet<OperationType> s = EnumSet.noneOf(OperationType.class);
      s.addAll(operationTypes);
      retryOperationTypes.set(Collections.unmodifiableSet(s));
    }
  }



  /**
   * Indicates whether the provided connection should be considered expired.
   *
   * @param  connection  The connection for which to make the determination.
   *
   * @return  {@code true} if the provided connection should be considered
   *          expired, or {@code false} if not.
   */
  private boolean connectionIsExpired(@NotNull final LDAPConnection connection)
  {
    // If connection expiration is not enabled, then there is nothing to do.
    if (maxConnectionAge <= 0L)
    {
      return false;
    }

    // If there is a minimum disconnect interval, then make sure that we have
    // not closed another expired connection too recently.
    final long currentTime = System.currentTimeMillis();
    if ((currentTime - lastExpiredDisconnectTime) < minDisconnectInterval)
    {
      return false;
    }

    // Get the age of the connection and see if it is expired.
    final long connectionAge = currentTime - connection.getConnectTime();
    return (connectionAge > maxConnectionAge);
  }



  /**
   * Specifies the bind request that will be used to authenticate subsequent new
   * connections that are established by this connection pool.  The
   * authentication state for existing connections will not be altered unless
   * one of the {@code bindAndRevertAuthentication} or
   * {@code releaseAndReAuthenticateConnection} methods are invoked on those
   * connections.
   *
   * @param  bindRequest  The bind request that will be used to authenticate new
   *                      connections that are established by this pool, or
   *                      that will be applied to existing connections via the
   *                      {@code bindAndRevertAuthentication} or
   *                      {@code releaseAndReAuthenticateConnection} method.  It
   *                      may be {@code null} if new connections should be
   *                      unauthenticated.
   */
  public void setBindRequest(@Nullable final BindRequest bindRequest)
  {
    this.bindRequest = bindRequest;
  }



  /**
   * Specifies the server set that should be used to establish new connections
   * for use in this connection pool.  Existing connections will not be
   * affected.
   *
   * @param  serverSet  The server set that should be used to establish new
   *                    connections for use in this connection pool.  It must
   *                    not be {@code null}.
   */
  public void setServerSet(@NotNull final ServerSet serverSet)
  {
    Validator.ensureNotNull(serverSet);
    this.serverSet = serverSet;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getConnectionPoolName()
  {
    return connectionPoolName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setConnectionPoolName(@Nullable final String connectionPoolName)
  {
    this.connectionPoolName = connectionPoolName;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that a connection in
   * this pool may be established before it is closed and replaced with another
   * connection.
   *
   * @return  The maximum length of time in milliseconds that a connection in
   *          this pool may be established before it is closed and replaced with
   *          another connection, or {@code 0L} if no maximum age should be
   *          enforced.
   */
  public long getMaxConnectionAgeMillis()
  {
    return maxConnectionAge;
  }



  /**
   * Specifies the maximum length of time in milliseconds that a connection in
   * this pool may be established before it should be closed and replaced with
   * another connection.
   *
   * @param  maxConnectionAge  The maximum length of time in milliseconds that a
   *                           connection in this pool may be established before
   *                           it should be closed and replaced with another
   *                           connection.  A value of zero indicates that no
   *                           maximum age should be enforced.
   */
  public void setMaxConnectionAgeMillis(final long maxConnectionAge)
  {
    if (maxConnectionAge > 0L)
    {
      this.maxConnectionAge = maxConnectionAge;
    }
    else
    {
      this.maxConnectionAge = 0L;
    }
  }



  /**
   * Retrieves the minimum length of time in milliseconds that should pass
   * between connections closed because they have been established for longer
   * than the maximum connection age.
   *
   * @return  The minimum length of time in milliseconds that should pass
   *          between connections closed because they have been established for
   *          longer than the maximum connection age, or {@code 0L} if expired
   *          connections may be closed as quickly as they are identified.
   */
  public long getMinDisconnectIntervalMillis()
  {
    return minDisconnectInterval;
  }



  /**
   * Specifies the minimum length of time in milliseconds that should pass
   * between connections closed because they have been established for longer
   * than the maximum connection age.
   *
   * @param  minDisconnectInterval  The minimum length of time in milliseconds
   *                                that should pass between connections closed
   *                                because they have been established for
   *                                longer than the maximum connection age.  A
   *                                value less than or equal to zero indicates
   *                                that no minimum time should be enforced.
   */
  public void setMinDisconnectIntervalMillis(final long minDisconnectInterval)
  {
    if (minDisconnectInterval > 0)
    {
      this.minDisconnectInterval = minDisconnectInterval;
    }
    else
    {
      this.minDisconnectInterval = 0L;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnectionPoolHealthCheck getHealthCheck()
  {
    return healthCheck;
  }



  /**
   * Sets the health check implementation for this connection pool.
   *
   * @param  healthCheck  The health check implementation for this connection
   *                      pool.  It must not be {@code null}.
   */
  public void setHealthCheck(
                   @NotNull final LDAPConnectionPoolHealthCheck healthCheck)
  {
    Validator.ensureNotNull(healthCheck);
    this.healthCheck = healthCheck;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public long getHealthCheckIntervalMillis()
  {
    return healthCheckInterval;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setHealthCheckIntervalMillis(final long healthCheckInterval)
  {
    Validator.ensureTrue(healthCheckInterval > 0L,
         "LDAPConnectionPool.healthCheckInterval must be greater than 0.");
    this.healthCheckInterval = healthCheckInterval;
    healthCheckThread.wakeUp();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void doHealthCheck()
  {
    final Iterator<Map.Entry<Thread,LDAPConnection>> iterator =
         connections.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<Thread,LDAPConnection> e = iterator.next();
      final Thread                           t = e.getKey();
      final LDAPConnection                   c = e.getValue();

      if (! t.isAlive())
      {
        c.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED, null,
                            null);
        c.terminate(null);
        iterator.remove();
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getCurrentAvailableConnections()
  {
    return -1;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getMaximumAvailableConnections()
  {
    return -1;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnectionPoolStatistics getConnectionPoolStatistics()
  {
    return poolStatistics;
  }



  /**
   * Closes this connection pool in the event that it becomes unreferenced.
   *
   * @throws  Throwable  If an unexpected problem occurs.
   */
  @Override()
  protected void finalize()
            throws Throwable
  {
    super.finalize();

    close();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPThreadLocalConnectionPool(");

    final String name = connectionPoolName;
    if (name != null)
    {
      buffer.append("name='");
      buffer.append(name);
      buffer.append("', ");
    }

    buffer.append("serverSet=");
    serverSet.toString(buffer);
    buffer.append(')');
  }
}
