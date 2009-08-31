/*
 * Copyright 2007-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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
import java.util.HashSet;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides an implementation of an LDAP connection pool, which is a
 * structure that can hold multiple connections established to a given server
 * that can be reused for multiple operations rather than creating and
 * destroying connections for each operation.  This connection pool
 * implementation provides traditional methods for checking out and releasing
 * connections, but it also provides wrapper methods that make it easy to
 * perform operations using pooled connections without the need to explicitly
 * check out or release the connections.
 * <BR><BR>
 * Note that both the {@code LDAPConnectionPool} class and the
 * {@link LDAPConnection} class implement the {@link LDAPInterface} interface.
 * This is a common interface that defines a number of common methods for
 * processing LDAP requests.  This means that in many cases, an application can
 * use an object of type {@link LDAPInterface} rather than
 * {@link LDAPConnection}, which makes it possible to work with either a single
 * standalone connection or with a connection pool.
 * <BR><BR>
 * <H2>Creating a Connection Pool</H2>
 * An LDAP connection pool can be created from either a single
 * {@link LDAPConnection} (for which an appropriate number of copies will be
 * created to fill out the pool) or using a {@link ServerSet} to create
 * connections that may span multiple servers.  For example:
 * <BR><BR>
 * <PRE>
 *   // Create a new LDAP connection pool with ten connections established and
 *   // authenticated to the same server:
 *   LDAPConnection connection = new LDAPConnection(address, port);
 *   BindResult bindResult = connection.bind(bindDN, password);
 *   LDAPConnectionPool connectionPool = new LDAPConnectionPool(connection, 10);
 *
 *   // Create a new LDAP connection pool with 10 connections spanning multiple
 *   // servers using a server set.
 *   RoundRobinServerSet serverSet = new RoundRobinServerSet(addresses, ports);
 *   SimpleBindRequest bindRequest = new SimpleBindRequest(bindDN, password);
 *   LDAPConnectionPool connectionPool =
 *        new LDAPConnectionPool(serverSet, bindRequest, 10);
 * </PRE>
 * Note that in some cases, such as when using StartTLS, it may be necessary to
 * perform some additional processing when a new connection is created for use
 * in the connection pool.  In this case, a {@link PostConnectProcessor} should
 * be provided to accomplish this.  See the documentation for the
 * {@link StartTLSPostConnectProcessor} class for an example that demonstrates
 * its use for creating a connection pool with connections secured using
 * StartTLS.
 * <BR><BR>
 * <H2>Processing Operations with a Connection Pool</H2>
 * If a single operation is to be processed using a connection from the
 * connection pool, then it can be used without the need to check out or release
 * a connection or perform any validity checking on the connection.  This can
 * be accomplished via the {@link LDAPInterface} interface that allows a
 * connection pool to be treated like a single connection.  For example, to
 * perform a search using a pooled connection:
 * <PRE>
 *   SearchResult searchResult =
 *        connectionPool.search("dc=example,dc=com", SearchScope.SUB,
 *                              "(uid=john.doe)");
 * </PRE>
 * If an application needs to process multiple operations using a single
 * connection, then it may be beneficial to obtain a connection from the pool
 * to use for processing those operations and then return it back to the pool
 * when it is no longer needed.  This can be done using the
 * {@link #getConnection} and {@link #releaseConnection} methods.  If during
 * processing it is determined that the connection is no longer valid, then the
 * connection should be released back to the pool using the
 * {@link #releaseDefunctConnection} method, which will ensure that the
 * connection is closed and a new connection will be established to take its
 * place in the pool.
 * <BR><BR>
 * Note that it is also possible to process multiple operations on a single
 * connection using the {@link #processRequests} method.  This may be useful if
 * a fixed set of operations should be processed over the same connection and
 * none of the subsequent requests depend upon the results of the earlier
 * operations.
 * <BR><BR>
 * Connection pools should generally not be used when performing operations that
 * may change the state of the underlying connections.  This is particularly
 * true for bind operations and the StartTLS extended operation, but it may
 * apply to other types of operations as well.
 * <BR><BR>
 * Performing a bind operation using a connection from the pool will invalidate
 * any previous authentication on that connection, and if that connection is
 * released back to the pool then subsequent operation attempts may fail or
 * be processed in an incorrect manner.  Bind operations should only be
 * performed in a connection pool if the pool is to be used exclusively for
 * processing binds, or if the bind request is specially crafted so that it will
 * not change the identity of the associated connection (e.g., by including the
 * retain identity request control in the bind request).
 * <BR><BR>
 * The StartTLS extended operation should never be invoked on a connection which
 * is part of a connection pool.  It is acceptable for the pool to maintain
 * connections which have been configured with StartTLS security prior to being
 * added to the pool (via the use of the {@link StartTLSPostConnectProcessor}).
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPConnectionPool
       extends AbstractConnectionPool
{
  /**
   * The default health check interval for this connection pool, which is set to
   * 60000 milliseconds (60 seconds).
   */
  private static final long DEFAULT_HEALTH_CHECK_INTERVAL = 60000L;



  // A counter used to keep track of the number of times that the pool failed to
  // replace a defunct connection.  It may also be initialized to the difference
  // between the initial and maximum number of connections that should be
  // included in the pool.
  private final AtomicInteger failedReplaceCount;

  // Indicates whether this connection pool has been closed.
  private volatile boolean closed;

  // Indicates whether to create a new connection if necessary rather than
  // waiting for a connection to become available.
  private boolean createIfNecessary;

  // The bind request to use to perform authentication whenever a new connection
  // is established.
  private final BindRequest bindRequest;

  // The number of connections to be held in this pool.
  private final int numConnections;

  // The health check implementation that should be used for this connection
  // pool.
  private LDAPConnectionPoolHealthCheck healthCheck;

  // The thread that will be used to perform periodic background health checks
  // for this connection pool.
  private final LDAPConnectionPoolHealthCheckThread healthCheckThread;

  // The statistics for this connection pool.
  private final LDAPConnectionPoolStatistics poolStatistics;

  // The set of connections that are currently available for use.
  private final LinkedBlockingQueue<LDAPConnection> availableConnections;

  // The length of time in milliseconds between periodic health checks against
  // the available connections in this pool.
  private volatile long healthCheckInterval;

  // The maximum length of time in milliseconds that a connection should be
  // allowed to be established before terminating and re-establishing the
  // connection.
  private volatile long maxConnectionAge;

  // The maximum length of time in milliseconds to wait for a connection to be
  // available.
  private long maxWaitTime;

  // The post-connect processor for this connection pool, if any.
  private final PostConnectProcessor postConnectProcessor;

  // The server set to use for establishing connections for use by this pool.
  private final ServerSet serverSet;

  // The user-friendly name assigned to this connection pool.
  private String connectionPoolName;




  /**
   * Creates a new LDAP connection pool with up to the specified number of
   * connections, created as clones of the provided connection.  Initially, only
   * the provided connection will be included in the pool, but additional
   * connections will be created as needed until the pool has reached its full
   * capacity, at which point the create if necessary and max wait time settings
   * will be used to determine how to behave if a connection is requested but
   * none are available.
   *
   * @param  connection      The connection to use to provide the template for
   *                         the other connections to be created.  This
   *                         connection will be included in the pool.  It must
   *                         not be {@code null}, and it must be established to
   *                         the target server.  It does not necessarily need to
   *                         be authenticated if all connections in the pool are
   *                         to be unauthenticated.
   * @param  numConnections  The total number of connections that should be
   *                         created in the pool.  It must be greater than or
   *                         equal to one.
   *
   * @throws  LDAPException  If the provided connection cannot be used to
   *                         initialize the pool, or if a problem occurs while
   *                         attempting to establish any of the connections.  If
   *                         this is thrown, then all connections associated
   *                         with the pool (including the one provided as an
   *                         argument) will be closed.
   */
  public LDAPConnectionPool(final LDAPConnection connection,
                            final int numConnections)
         throws LDAPException
  {
    this(connection, 1, numConnections, null);
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created as clones of the provided connection.
   *
   * @param  connection          The connection to use to provide the template
   *                             for the other connections to be created.  This
   *                             connection will be included in the pool.  It
   *                             must not be {@code null}, and it must be
   *                             established to the target server.  It does not
   *                             necessarily need to be authenticated if all
   *                             connections in the pool are to be
   *                             unauthenticated.
   * @param  initialConnections  The number of connections to initially
   *                             establish when the pool is created.  It must be
   *                             greater than or equal to one.
   * @param  maxConnections      The maximum number of connections that should
   *                             be maintained in the pool.  It must be greater
   *                             than or equal to the initial number of
   *                             connections.
   *
   * @throws  LDAPException  If the provided connection cannot be used to
   *                         initialize the pool, or if a problem occurs while
   *                         attempting to establish any of the connections.  If
   *                         this is thrown, then all connections associated
   *                         with the pool (including the one provided as an
   *                         argument) will be closed.
   */
  public LDAPConnectionPool(final LDAPConnection connection,
                            final int initialConnections,
                            final int maxConnections)
         throws LDAPException
  {
    this(connection, initialConnections, maxConnections, null);
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created as clones of the provided connection.
   *
   * @param  connection            The connection to use to provide the template
   *                               for the other connections to be created.
   *                               This connection will be included in the pool.
   *                               It must not be {@code null}, and it must be
   *                               established to the target server.  It does
   *                               not necessarily need to be authenticated if
   *                               all connections in the pool are to be
   *                               unauthenticated.
   * @param  initialConnections    The number of connections to initially
   *                               establish when the pool is created.  It must
   *                               be greater than or equal to one.
   * @param  maxConnections        The maximum number of connections that should
   *                               be maintained in the pool.  It must be
   *                               greater than or equal to the initial number
   *                               of connections.
   * @param  postConnectProcessor  A processor that should be used to perform
   *                               any post-connect processing for connections
   *                               in this pool.  It may be {@code null} if no
   *                               special processing is needed.  Note that this
   *                               processing will not be invoked on the
   *                               provided connection that will be used as the
   *                               first connection in the pool.
   *
   * @throws  LDAPException  If the provided connection cannot be used to
   *                         initialize the pool, or if a problem occurs while
   *                         attempting to establish any of the connections.  If
   *                         this is thrown, then all connections associated
   *                         with the pool (including the one provided as an
   *                         argument) will be closed.
   */
  public LDAPConnectionPool(final LDAPConnection connection,
                            final int initialConnections,
                            final int maxConnections,
                            final PostConnectProcessor postConnectProcessor)
         throws LDAPException
  {
    ensureNotNull(connection);
    ensureTrue(initialConnections >= 1,
               "LDAPConnectionPool.initialConnections must be at least 1.");
    ensureTrue(maxConnections >= initialConnections,
               "LDAPConnectionPool.initialConnections must not be greater " +
                    "than maxConnections.");

    this.postConnectProcessor = postConnectProcessor;

    healthCheck         = new LDAPConnectionPoolHealthCheck();
    healthCheckInterval = DEFAULT_HEALTH_CHECK_INTERVAL;
    poolStatistics      = new LDAPConnectionPoolStatistics(this);
    connectionPoolName  = null;

    if (! connection.isConnected())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
                              ERR_POOL_CONN_NOT_ESTABLISHED.get());
    }


    serverSet = new SingleServerSet(connection.getConnectedAddress(),
                                    connection.getConnectedPort(),
                                    connection.getLastUsedSocketFactory(),
                                    connection.getConnectionOptions());
    bindRequest = connection.getLastBindRequest();

    final ArrayList<LDAPConnection> connList =
         new ArrayList<LDAPConnection>(initialConnections);
    connection.setConnectionName(null);
    connection.setConnectionPool(this);
    connList.add(connection);
    for (int i=1; i < initialConnections; i++)
    {
      try
      {
        connList.add(createConnection());
      }
      catch (LDAPException le)
      {
        debugException(le);
        for (final LDAPConnection c : connList)
        {
          try
          {
            c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null, le);
            c.terminate(null);
          }
          catch (Exception e)
          {
            debugException(e);
          }
        }

        throw le;
      }
    }

    numConnections = maxConnections;

    availableConnections =
         new LinkedBlockingQueue<LDAPConnection>(numConnections);
    availableConnections.addAll(connList);

    failedReplaceCount = new AtomicInteger(maxConnections - initialConnections);
    createIfNecessary  = true;
    maxConnectionAge   = 0L;
    maxWaitTime        = 5000L;
    closed             = false;

    healthCheckThread = new LDAPConnectionPoolHealthCheckThread(this);
    healthCheckThread.start();
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created using the provided server set.  Initially, only
   * one will be created and included in the pool, but additional connections
   * will be created as needed until the pool has reached its full capacity, at
   * which point the create if necessary and max wait time settings will be used
   * to determine how to behave if a connection is requested but none are
   * available.
   *
   * @param  serverSet       The server set to use to create the connections.
   *                         It is acceptable for the server set to create the
   *                         connections across multiple servers.
   * @param  bindRequest     The bind request to use to authenticate the
   *                         connections that are established.  It may be
   *                         {@code null} if no authentication should be
   *                         performed on the connections.
   * @param  numConnections  The total number of connections that should be
   *                         created in the pool.  It must be greater than or
   *                         equal to one.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         any of the connections.  If this is thrown, then
   *                         all connections associated with the pool will be
   *                         closed.
   */
  public LDAPConnectionPool(final ServerSet serverSet,
                            final BindRequest bindRequest,
                            final int numConnections)
         throws LDAPException
  {
    this(serverSet, bindRequest, 1, numConnections, null);
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created using the provided server set.
   *
   * @param  serverSet           The server set to use to create the
   *                             connections.  It is acceptable for the server
   *                             set to create the connections across multiple
   *                             servers.
   * @param  bindRequest         The bind request to use to authenticate the
   *                             connections that are established.  It may be
   *                             {@code null} if no authentication should be
   *                             performed on the connections.
   * @param  initialConnections  The number of connections to initially
   *                             establish when the pool is created.  It must be
   *                             greater than or equal to one.
   * @param  maxConnections      The maximum number of connections that should
   *                             be maintained in the pool.  It must be greater
   *                             than or equal to the initial number of
   *                             connections.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         any of the connections.  If this is thrown, then
   *                         all connections associated with the pool will be
   *                         closed.
   */
  public LDAPConnectionPool(final ServerSet serverSet,
                            final BindRequest bindRequest,
                            final int initialConnections,
                            final int maxConnections)
         throws LDAPException
  {
    this(serverSet, bindRequest, initialConnections, maxConnections, null);
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created using the provided server set.
   *
   * @param  serverSet             The server set to use to create the
   *                               connections.  It is acceptable for the server
   *                               set to create the connections across multiple
   *                               servers.
   * @param  bindRequest           The bind request to use to authenticate the
   *                               connections that are established.  It may be
   *                               {@code null} if no authentication should be
   *                               performed on the connections.
   * @param  initialConnections    The number of connections to initially
   *                               establish when the pool is created.  It must
   *                               be greater than or equal to one.
   * @param  maxConnections        The maximum number of connections that should
   *                               be maintained in the pool.  It must be
   *                               greater than or equal to the initial number
   *                               of connections.
   * @param  postConnectProcessor  A processor that should be used to perform
   *                               any post-connect processing for connections
   *                               in this pool.  It may be {@code null} if no
   *                               special processing is needed.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         any of the connections.  If this is thrown, then
   *                         all connections associated with the pool will be
   *                         closed.
   */
  public LDAPConnectionPool(final ServerSet serverSet,
                            final BindRequest bindRequest,
                            final int initialConnections,
                            final int maxConnections,
                            final PostConnectProcessor postConnectProcessor)
         throws LDAPException
  {
    ensureNotNull(serverSet);
    ensureTrue(initialConnections >= 1,
               "LDAPConnectionPool.initialConnections must be at least 1.");
    ensureTrue(maxConnections >= initialConnections,
               "LDAPConnectionPool.initialConnections must not be greater " +
                    "than maxConnections.");

    this.serverSet            = serverSet;
    this.bindRequest          = bindRequest;
    this.postConnectProcessor = postConnectProcessor;

    healthCheck         = new LDAPConnectionPoolHealthCheck();
    healthCheckInterval = DEFAULT_HEALTH_CHECK_INTERVAL;
    poolStatistics      = new LDAPConnectionPoolStatistics(this);
    connectionPoolName  = null;

    final ArrayList<LDAPConnection> connList =
         new ArrayList<LDAPConnection>(initialConnections);
    for (int i=0; i < initialConnections; i++)
    {
      try
      {
        connList.add(createConnection());
      }
      catch (LDAPException le)
      {
        debugException(le);
        for (final LDAPConnection c : connList)
        {
          try
          {
            c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null, le);
            c.terminate(null);
          } catch (Exception e)
          {
            debugException(e);
          }
        }

        throw le;
      }
    }

    numConnections = maxConnections;

    availableConnections =
         new LinkedBlockingQueue<LDAPConnection>(numConnections);
    availableConnections.addAll(connList);

    failedReplaceCount = new AtomicInteger(maxConnections - initialConnections);
    createIfNecessary  = true;
    maxConnectionAge   = 0L;
    maxWaitTime        = 5000L;
    closed             = false;

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
  private LDAPConnection createConnection()
          throws LDAPException
  {
    final LDAPConnection c = serverSet.getConnection(healthCheck);
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

    if (postConnectProcessor != null)
    {
      try
      {
        postConnectProcessor.processPreAuthenticatedConnection(c);
      }
      catch (Exception e)
      {
        debugException(e);

        try
        {
          poolStatistics.incrementNumFailedConnectionAttempts();
          c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null, e);
          c.terminate(null);
        }
        catch (Exception e2)
        {
          debugException(e2);
        }

        if (e instanceof LDAPException)
        {
          throw ((LDAPException) e);
        }
        else
        {
          throw new LDAPException(ResultCode.CONNECT_ERROR,
               ERR_POOL_POST_CONNECT_ERROR.get(getExceptionMessage(e)), e);
        }
      }
    }

    try
    {
      if (bindRequest != null)
      {
        c.bind(bindRequest.duplicate());
      }
    }
    catch (Exception e)
    {
      debugException(e);
      try
      {
        poolStatistics.incrementNumFailedConnectionAttempts();
        c.setDisconnectInfo(DisconnectType.BIND_FAILED, null, e);
        c.terminate(null);
      }
      catch (Exception e2)
      {
        debugException(e2);
      }

      if (e instanceof LDAPException)
      {
        throw ((LDAPException) e);
      }
      else
      {
        throw new LDAPException(ResultCode.CONNECT_ERROR,
             ERR_POOL_CONNECT_ERROR.get(getExceptionMessage(e)), e);
      }
    }

    if (postConnectProcessor != null)
    {
      try
      {
        postConnectProcessor.processPostAuthenticatedConnection(c);
      }
      catch (Exception e)
      {
        debugException(e);
        try
        {
          poolStatistics.incrementNumFailedConnectionAttempts();
          c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null, e);
          c.terminate(null);
        }
        catch (Exception e2)
        {
          debugException(e2);
        }

        if (e instanceof LDAPException)
        {
          throw ((LDAPException) e);
        }
        else
        {
          throw new LDAPException(ResultCode.CONNECT_ERROR,
               ERR_POOL_POST_CONNECT_ERROR.get(getExceptionMessage(e)), e);
        }
      }
    }

    c.setConnectionPoolName(connectionPoolName);
    poolStatistics.incrementNumSuccessfulConnectionAttempts();
    return c;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void close()
  {
    closed = true;
    healthCheckThread.stopRunning();

    while (true)
    {
      final LDAPConnection conn = availableConnections.poll();
      if (conn == null)
      {
        return;
      }
      else
      {
        poolStatistics.incrementNumConnectionsClosedUnneeded();
        conn.setDisconnectInfo(DisconnectType.POOL_CLOSED, null, null);
        conn.terminate(null);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPConnection getConnection()
         throws LDAPException
  {
    if (closed)
    {
      poolStatistics.incrementNumFailedCheckouts();
      throw new LDAPException(ResultCode.CONNECT_ERROR,
                              ERR_POOL_CLOSED.get());
    }

    LDAPConnection conn = availableConnections.poll();
    if (conn != null)
    {
      if (conn.isConnected())
      {
        try
        {
          healthCheck.ensureConnectionValidForCheckout(conn);
          poolStatistics.incrementNumSuccessfulCheckoutsWithoutWaiting();
          return conn;
        }
        catch (LDAPException le)
        {
          debugException(le);
        }
      }

      handleDefunctConnection(conn);
      for (int i=0; i < numConnections; i++)
      {
        conn = availableConnections.poll();
        if (conn == null)
        {
          break;
        }
        else if (conn.isConnected())
        {
          try
          {
            healthCheck.ensureConnectionValidForCheckout(conn);
            poolStatistics.incrementNumSuccessfulCheckoutsWithoutWaiting();
            return conn;
          }
          catch (LDAPException le)
          {
            debugException(le);
            handleDefunctConnection(conn);
          }
        }
        else
        {
          handleDefunctConnection(conn);
        }
      }
    }

    if (failedReplaceCount.get() > 0)
    {
      final int newReplaceCount = failedReplaceCount.getAndDecrement();
      if (newReplaceCount > 0)
      {
        try
        {
          conn = createConnection();
          poolStatistics.incrementNumSuccessfulCheckoutsNewConnection();
          return conn;
        }
        catch (LDAPException le)
        {
          debugException(le);
          failedReplaceCount.incrementAndGet();
          poolStatistics.incrementNumFailedCheckouts();
          throw le;
        }
      }
      else
      {
        failedReplaceCount.incrementAndGet();
        poolStatistics.incrementNumFailedCheckouts();
        throw new LDAPException(ResultCode.CONNECT_ERROR,
                                ERR_POOL_NO_CONNECTIONS.get());
      }
    }

    if (maxWaitTime > 0)
    {
      try
      {
        conn = availableConnections.poll(maxWaitTime, TimeUnit.MILLISECONDS);
        if (conn != null)
        {
          try
          {
            healthCheck.ensureConnectionValidForCheckout(conn);
            poolStatistics.incrementNumSuccessfulCheckoutsAfterWaiting();
            return conn;
          }
          catch (LDAPException le)
          {
            debugException(le);
            handleDefunctConnection(conn);
          }
        }
      }
      catch (InterruptedException ie)
      {
        debugException(ie);
      }
    }

    if (createIfNecessary)
    {
      try
      {
        conn = createConnection();
        poolStatistics.incrementNumSuccessfulCheckoutsNewConnection();
        return conn;
      }
      catch (LDAPException le)
      {
        debugException(le);
        poolStatistics.incrementNumFailedCheckouts();
        throw le;
      }
    }
    else
    {
      poolStatistics.incrementNumFailedCheckouts();
      throw new LDAPException(ResultCode.CONNECT_ERROR,
                              ERR_POOL_NO_CONNECTIONS.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void releaseConnection(final LDAPConnection connection)
  {
    if (connection == null)
    {
      return;
    }

    connection.setConnectionPoolName(connectionPoolName);
    if ((maxConnectionAge > 0L) &&
        ((System.currentTimeMillis() - connection.getConnectTime()) >
         maxConnectionAge))
    {
      connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_EXPIRED,
                                   null, null);
      poolStatistics.incrementNumConnectionsClosedExpired();
      handleDefunctConnection(connection);
      return;
    }

    try
    {
      healthCheck.ensureConnectionValidForRelease(connection);
    }
    catch (LDAPException le)
    {
      releaseDefunctConnection(connection);
      return;
    }

    if (availableConnections.offer(connection))
    {
      poolStatistics.incrementNumReleasedValid();
    }
    else
    {
      // This means that the connection pool is full, which can happen if the
      // pool was empty when a request came in to retrieve a connection and
      // createIfNecessary was true.  In this case, we'll just close the
      // connection since we don't need it any more.
      connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                                   null, null);
      poolStatistics.incrementNumConnectionsClosedUnneeded();
      connection.terminate(null);
      return;
    }

    if (closed)
    {
      close();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void releaseDefunctConnection(final LDAPConnection connection)
  {
    if (connection == null)
    {
      return;
    }

    connection.setConnectionPoolName(connectionPoolName);
    poolStatistics.incrementNumConnectionsClosedDefunct();
    handleDefunctConnection(connection);
  }



  /**
   * Performs the real work of terminating a defunct connection and replacing it
   * with a new connection if possible.
   *
   * @param  connection  The defunct connection to be replaced.
   *
   * @return  The new connection created to take the place of the defunct
   *          connection, or {@code null} if no new connection was created.
   *          Note that if a connection is returned, it will have already been
   *          made available and the caller must not rely on it being unused for
   *          any other purpose.
   */
  private LDAPConnection handleDefunctConnection(
                              final LDAPConnection connection)
  {
    connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, null,
                                 null);
    connection.terminate(null);

    if (closed)
    {
      return null;
    }

    if (createIfNecessary && (availableConnections.remainingCapacity() <= 0))
    {
      return null;
    }

    try
    {
      final LDAPConnection conn = createConnection();
      if (! availableConnections.offer(conn))
      {
        conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                               null, null);
        conn.terminate(null);
        return null;
      }

      return conn;
    }
    catch (LDAPException le)
    {
      debugException(le);
      failedReplaceCount.incrementAndGet();
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getConnectionPoolName()
  {
    return connectionPoolName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setConnectionPoolName(final String connectionPoolName)
  {
    this.connectionPoolName = connectionPoolName;
    for (final LDAPConnection c : availableConnections)
    {
      c.setConnectionPoolName(connectionPoolName);
    }
  }



  /**
   * Indicates whether the connection pool should create a new connection if one
   * is requested when there are none available.
   *
   * @return  {@code true} if a new connection should be created if none are
   *          available when a request is received, or {@code false} if an
   *          exception should be thrown to indicate that no connection is
   *          available.
   */
  public boolean getCreateIfNecessary()
  {
    return createIfNecessary;
  }



  /**
   * Specifies whether the connection pool should create a new connection if one
   * is requested when there are none available.
   *
   * @param  createIfNecessary  Specifies whether the connection pool should
   *                            create a new connection if one is requested when
   *                            there are none available.
   */
  public void setCreateIfNecessary(final boolean createIfNecessary)
  {
    this.createIfNecessary = createIfNecessary;
  }



  /**
   * Retrieves the maximum length of time in milliseconds to wait for a
   * connection to become available when trying to obtain a connection from the
   * pool.
   *
   * @return  The maximum length of time in milliseconds to wait for a
   *          connection to become available when trying to obtain a connection
   *          from the pool, or zero to indicate that the pool should not block
   *          at all if no connections are available and that it should either
   *          create a new connection or throw an exception.
   */
  public long getMaxWaitTimeMillis()
  {
    return maxWaitTime;
  }



  /**
   * Specifies the maximum length of time in milliseconds to wait for a
   * connection to become available when trying to obtain a connection from the
   * pool.
   *
   * @param  maxWaitTime  The maximum length of time in milliseconds to wait for
   *                      a connection to become available when trying to obtain
   *                      a connection from the pool.  A value of zero should be
   *                      used to indicate that the pool should not block at all
   *                      if no connections are available and that it should
   *                      either create a new connection or throw an exception.
   */
  public void setMaxWaitTimeMillis(final long maxWaitTime)
  {
    if (maxWaitTime > 0L)
    {
      this.maxWaitTime = maxWaitTime;
    }
    else
    {
      this.maxWaitTime = 0L;
    }
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
   * {@inheritDoc}
   */
  @Override()
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
  public void setHealthCheck(final LDAPConnectionPoolHealthCheck healthCheck)
  {
    ensureNotNull(healthCheck);
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
    ensureTrue(healthCheckInterval > 0L,
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
    // Create a set used to hold connections that we've already examined.  If we
    // encounter the same connection twice, then we know that we don't need to
    // do any more work.
    final HashSet<LDAPConnection> examinedConnections =
         new HashSet<LDAPConnection>(numConnections);

    for (int i=0; i < numConnections; i++)
    {
      LDAPConnection conn = availableConnections.poll();
      if (conn == null)
      {
        break;
      }
      else if (examinedConnections.contains(conn))
      {
        if (! availableConnections.offer(conn))
        {
          conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                                 null, null);
          poolStatistics.incrementNumConnectionsClosedUnneeded();
          conn.terminate(null);
        }
        break;
      }

      if (! conn.isConnected())
      {
        conn = handleDefunctConnection(conn);
        if (conn != null)
        {
          examinedConnections.add(conn);
        }
      }
      else if ((maxConnectionAge > 0L) &&
               ((System.currentTimeMillis() - conn.getConnectTime()) >=
                maxConnectionAge))
      {
        conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_EXPIRED, null,
                               null);
        poolStatistics.incrementNumConnectionsClosedExpired();
        conn = handleDefunctConnection(conn);
        if (conn != null)
        {
          examinedConnections.add(conn);
        }
      }
      else
      {
        try
        {
          healthCheck.ensureConnectionValidForContinuedUse(conn);
          if (availableConnections.offer(conn))
          {
            examinedConnections.add(conn);
          }
          else
          {
            conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                                   null, null);
            poolStatistics.incrementNumConnectionsClosedUnneeded();
            conn.terminate(null);
          }
        }
        catch (Exception e)
        {
          debugException(e);
          conn = handleDefunctConnection(conn);
          if (conn != null)
          {
            examinedConnections.add(conn);
          }
        }
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getCurrentAvailableConnections()
  {
    return availableConnections.size();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getMaximumAvailableConnections()
  {
    return numConnections;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
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
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPConnectionPool(");

    final String name = connectionPoolName;
    if (name != null)
    {
      buffer.append("name='");
      buffer.append(name);
      buffer.append("', ");
    }

    buffer.append("serverSet=");
    serverSet.toString(buffer);
    buffer.append(", maxConnections=");
    buffer.append(numConnections);
    buffer.append(')');
  }
}
