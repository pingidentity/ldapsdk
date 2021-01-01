/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.protocol.LDAPResponse;
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
 * released back to the pool without first being re-authenticated as the
 * original user, then subsequent operation attempts may fail or be processed in
 * an incorrect manner.  Bind operations should only be performed in a
 * connection pool if the pool is to be used exclusively for processing binds,
 * if the bind request is specially crafted so that it will not change the
 * identity of the associated connection (e.g., by including the retain identity
 * request control in the bind request if using the LDAP SDK with a Ping
 * Identity, UnboundID, or Nokia/Alcatel-Lucent 8661 Directory Server), or if
 * the code using the connection pool makes sure to re-authenticate the
 * connection as the appropriate user whenever its identity has been changed.
 * <BR><BR>
 * The StartTLS extended operation should never be invoked on a connection which
 * is part of a connection pool.  It is acceptable for the pool to maintain
 * connections which have been configured with StartTLS security prior to being
 * added to the pool (via the use of the {@link StartTLSPostConnectProcessor}).
 * <BR><BR>
 * <H2>Pool Connection Management</H2>
 * When creating a connection pool, you may specify an initial number of
 * connections and a maximum number of connections.  The initial number of
 * connections is the number of connections that should be immediately
 * established and available for use when the pool is created.  The maximum
 * number of connections is the largest number of unused connections that may
 * be available in the pool at any time.
 * <BR><BR>
 * Whenever a connection is needed, whether by an attempt to check out a
 * connection or to use one of the pool's methods to process an operation, the
 * pool will first check to see if there is a connection that has already been
 * established but is not currently in use, and if so then that connection will
 * be used.  If there aren't any unused connections that are already
 * established, then the pool will determine if it has yet created the maximum
 * number of connections, and if not then it will immediately create a new
 * connection and use it.  If the pool has already created the maximum number
 * of connections, then the pool may wait for a period of time (as indicated by
 * the {@link #getMaxWaitTimeMillis()} method, which has a default value of zero
 * to indicate that it should not wait at all) for an in-use connection to be
 * released back to the pool.  If no connection is available after the specified
 * wait time (or there should not be any wait time), then the pool may
 * automatically create a new connection to use if
 * {@link #getCreateIfNecessary()} returns {@code true} (which is the default).
 * If it is able to successfully create a connection, then it will be used.  If
 * it cannot create a connection, or if {@code getCreateIfNecessary()} returns
 * {@code false}, then an {@link LDAPException} will be thrown.
 * <BR><BR>
 * Note that the maximum number of connections specified when creating a pool
 * refers to the maximum number of connections that should be available for use
 * at any given time.  If {@code getCreateIfNecessary()} returns {@code true},
 * then there may temporarily be more active connections than the configured
 * maximum number of connections.  This can be useful during periods of heavy
 * activity, because the pool will keep those connections established until the
 * number of unused connections exceeds the configured maximum.  If you wish to
 * enforce a hard limit on the maximum number of connections so that there
 * cannot be more than the configured maximum in use at any time, then use the
 * {@link #setCreateIfNecessary(boolean)} method to indicate that the pool
 * should not automatically create connections when one is needed but none are
 * available, and you may also want to use the
 * {@link #setMaxWaitTimeMillis(long)} method to specify a maximum wait time to
 * allow the pool to wait for a connection to become available rather than
 * throwing an exception if no connections are immediately available.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPConnectionPool
       extends AbstractConnectionPool
{
  /**
   * The default health check interval for this connection pool, which is set to
   * 60000 milliseconds (60 seconds).
   */
  private static final long DEFAULT_HEALTH_CHECK_INTERVAL = 60_000L;



  /**
   * The name of the connection property that may be used to indicate that a
   * particular connection should have a different maximum connection age than
   * the default for this pool.
   */
  @NotNull static final String ATTACHMENT_NAME_MAX_CONNECTION_AGE =
       LDAPConnectionPool.class.getName() + ".maxConnectionAge";



  // A counter used to keep track of the number of times that the pool failed to
  // replace a defunct connection.  It may also be initialized to the difference
  // between the initial and maximum number of connections that should be
  // included in the pool.
  @NotNull private final AtomicInteger failedReplaceCount;

  // The types of operations that should be retried if they fail in a manner
  // that may be the result of a connection that is no longer valid.
  @NotNull private final AtomicReference<Set<OperationType>>
       retryOperationTypes;

  // Indicates whether this connection pool has been closed.
  private volatile boolean closed;

  // Indicates whether to create a new connection if necessary rather than
  // waiting for a connection to become available.
  private boolean createIfNecessary;

  // Indicates whether to check the connection age when releasing a connection
  // back to the pool.
  private volatile boolean checkConnectionAgeOnRelease;

  // Indicates whether health check processing for connections in synchronous
  // mode should include attempting to read with a very short timeout to attempt
  // to detect closures and unsolicited notifications in a more timely manner.
  private volatile boolean trySynchronousReadDuringHealthCheck;

  // The bind request to use to perform authentication whenever a new connection
  // is established.
  @Nullable private volatile BindRequest bindRequest;

  // The number of connections to be held in this pool.
  private final int numConnections;

  // The minimum number of connections that the health check mechanism should
  // try to keep available for immediate use.
  private volatile int minConnectionGoal;

  // The health check implementation that should be used for this connection
  // pool.
  @NotNull private LDAPConnectionPoolHealthCheck healthCheck;

  // The thread that will be used to perform periodic background health checks
  // for this connection pool.
  @NotNull private final LDAPConnectionPoolHealthCheckThread healthCheckThread;

  // The statistics for this connection pool.
  @NotNull private final LDAPConnectionPoolStatistics poolStatistics;

  // The set of connections that are currently available for use.
  @NotNull private final LinkedBlockingQueue<LDAPConnection>
       availableConnections;

  // The length of time in milliseconds between periodic health checks against
  // the available connections in this pool.
  private volatile long healthCheckInterval;

  // The time that the last expired connection was closed.
  private volatile long lastExpiredDisconnectTime;

  // The maximum length of time in milliseconds that a connection should be
  // allowed to be established before terminating and re-establishing the
  // connection.
  private volatile long maxConnectionAge;

  // The maximum connection age that should be used for connections created to
  // replace connections that are released as defunct.
  @Nullable private volatile Long maxDefunctReplacementConnectionAge;

  // The maximum length of time in milliseconds to wait for a connection to be
  // available.
  private long maxWaitTime;

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
  public LDAPConnectionPool(@NotNull final LDAPConnection connection,
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
   *                             connections.  See the "Pool Connection
   *                             Management" section of the class-level
   *                             documentation for an explanation of how the
   *                             pool treats the maximum number of connections.
   *
   * @throws  LDAPException  If the provided connection cannot be used to
   *                         initialize the pool, or if a problem occurs while
   *                         attempting to establish any of the connections.  If
   *                         this is thrown, then all connections associated
   *                         with the pool (including the one provided as an
   *                         argument) will be closed.
   */
  public LDAPConnectionPool(@NotNull final LDAPConnection connection,
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
   *                               of connections.  See the "Pool Connection
   *                               Management" section of the class-level
   *                               documentation for an explanation of how the
   *                               pool treats the maximum number of
   *                               connections.
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
  public LDAPConnectionPool(@NotNull final LDAPConnection connection,
              final int initialConnections,
              final int maxConnections,
              @Nullable final PostConnectProcessor postConnectProcessor)
         throws LDAPException
  {
    this(connection, initialConnections, maxConnections,  postConnectProcessor,
         true);
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created as clones of the provided connection.
   *
   * @param  connection             The connection to use to provide the
   *                                template for the other connections to be
   *                                created.  This connection will be included
   *                                in the pool.  It must not be {@code null},
   *                                and it must be established to the target
   *                                server.  It does not necessarily need to be
   *                                authenticated if all connections in the pool
   *                                are to be unauthenticated.
   * @param  initialConnections     The number of connections to initially
   *                                establish when the pool is created.  It must
   *                                be greater than or equal to one.
   * @param  maxConnections         The maximum number of connections that
   *                                should be maintained in the pool.  It must
   *                                be greater than or equal to the initial
   *                                number of connections.  See the "Pool
   *                                Connection Management" section of the
   *                                class-level documentation for an explanation
   *                                of how the pool treats the maximum number of
   *                                connections.
   * @param  postConnectProcessor   A processor that should be used to perform
   *                                any post-connect processing for connections
   *                                in this pool.  It may be {@code null} if no
   *                                special processing is needed.  Note that
   *                                this processing will not be invoked on the
   *                                provided connection that will be used as the
   *                                first connection in the pool.
   * @param  throwOnConnectFailure  If an exception should be thrown if a
   *                                problem is encountered while attempting to
   *                                create the specified initial number of
   *                                connections.  If {@code true}, then the
   *                                attempt to create the pool will fail.if any
   *                                connection cannot be established.  If
   *                                {@code false}, then the pool will be created
   *                                but may have fewer than the initial number
   *                                of connections (or possibly no connections).
   *
   * @throws  LDAPException  If the provided connection cannot be used to
   *                         initialize the pool, or if a problem occurs while
   *                         attempting to establish any of the connections.  If
   *                         this is thrown, then all connections associated
   *                         with the pool (including the one provided as an
   *                         argument) will be closed.
   */
  public LDAPConnectionPool(@NotNull final LDAPConnection connection,
              final int initialConnections, final int maxConnections,
              @Nullable final PostConnectProcessor postConnectProcessor,
              final boolean throwOnConnectFailure)
         throws LDAPException
  {
    this(connection, initialConnections, maxConnections, 1,
         postConnectProcessor, throwOnConnectFailure);
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created as clones of the provided connection.
   *
   * @param  connection             The connection to use to provide the
   *                                template for the other connections to be
   *                                created.  This connection will be included
   *                                in the pool.  It must not be {@code null},
   *                                and it must be established to the target
   *                                server.  It does not necessarily need to be
   *                                authenticated if all connections in the pool
   *                                are to be unauthenticated.
   * @param  initialConnections     The number of connections to initially
   *                                establish when the pool is created.  It must
   *                                be greater than or equal to one.
   * @param  maxConnections         The maximum number of connections that
   *                                should be maintained in the pool.  It must
   *                                be greater than or equal to the initial
   *                                number of connections.  See the "Pool
   *                                Connection Management" section of the
   *                                class-level documentation for an
   *                                explanation of how the pool treats the
   *                                maximum number of connections.
   * @param  initialConnectThreads  The number of concurrent threads to use to
   *                                establish the initial set of connections.
   *                                A value greater than one indicates that the
   *                                attempt to establish connections should be
   *                                parallelized.
   * @param  postConnectProcessor   A processor that should be used to perform
   *                                any post-connect processing for connections
   *                                in this pool.  It may be {@code null} if no
   *                                special processing is needed.  Note that
   *                                this processing will not be invoked on the
   *                                provided connection that will be used as the
   *                                first connection in the pool.
   * @param  throwOnConnectFailure  If an exception should be thrown if a
   *                                problem is encountered while attempting to
   *                                create the specified initial number of
   *                                connections.  If {@code true}, then the
   *                                attempt to create the pool will fail.if any
   *                                connection cannot be established.  If
   *                                {@code false}, then the pool will be created
   *                                but may have fewer than the initial number
   *                                of connections (or possibly no connections).
   *
   * @throws  LDAPException  If the provided connection cannot be used to
   *                         initialize the pool, or if a problem occurs while
   *                         attempting to establish any of the connections.  If
   *                         this is thrown, then all connections associated
   *                         with the pool (including the one provided as an
   *                         argument) will be closed.
   */
  public LDAPConnectionPool(@NotNull final LDAPConnection connection,
              final int initialConnections, final int maxConnections,
              final int initialConnectThreads,
              @Nullable final PostConnectProcessor postConnectProcessor,
              final boolean throwOnConnectFailure)
         throws LDAPException
  {
    this(connection, initialConnections, maxConnections, initialConnectThreads,
         postConnectProcessor, throwOnConnectFailure, null);
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created as clones of the provided connection.
   *
   * @param  connection             The connection to use to provide the
   *                                template for the other connections to be
   *                                created.  This connection will be included
   *                                in the pool.  It must not be {@code null},
   *                                and it must be established to the target
   *                                server.  It does not necessarily need to be
   *                                authenticated if all connections in the pool
   *                                are to be unauthenticated.
   * @param  initialConnections     The number of connections to initially
   *                                establish when the pool is created.  It must
   *                                be greater than or equal to one.
   * @param  maxConnections         The maximum number of connections that
   *                                should be maintained in the pool.  It must
   *                                be greater than or equal to the initial
   *                                number of connections.  See the "Pool
   *                                Connection Management" section of the
   *                                class-level documentation for an explanation
   *                                of how the pool treats the maximum number of
   *                                connections.
   * @param  initialConnectThreads  The number of concurrent threads to use to
   *                                establish the initial set of connections.
   *                                A value greater than one indicates that the
   *                                attempt to establish connections should be
   *                                parallelized.
   * @param  postConnectProcessor   A processor that should be used to perform
   *                                any post-connect processing for connections
   *                                in this pool.  It may be {@code null} if no
   *                                special processing is needed.  Note that
   *                                this processing will not be invoked on the
   *                                provided connection that will be used as the
   *                                first connection in the pool.
   * @param  throwOnConnectFailure  If an exception should be thrown if a
   *                                problem is encountered while attempting to
   *                                create the specified initial number of
   *                                connections.  If {@code true}, then the
   *                                attempt to create the pool will fail.if any
   *                                connection cannot be established.  If
   *                                {@code false}, then the pool will be created
   *                                but may have fewer than the initial number
   *                                of connections (or possibly no connections).
   * @param  healthCheck            The health check that should be used for
   *                                connections in this pool.  It may be
   *                                {@code null} if the default health check
   *                                should be used.
   *
   * @throws  LDAPException  If the provided connection cannot be used to
   *                         initialize the pool, or if a problem occurs while
   *                         attempting to establish any of the connections.  If
   *                         this is thrown, then all connections associated
   *                         with the pool (including the one provided as an
   *                         argument) will be closed.
   */
  public LDAPConnectionPool(@NotNull final LDAPConnection connection,
              final int initialConnections, final int maxConnections,
              final int initialConnectThreads,
              @Nullable final PostConnectProcessor postConnectProcessor,
              final boolean throwOnConnectFailure,
              @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    Validator.ensureNotNull(connection);
    Validator.ensureTrue(initialConnections >= 1,
         "LDAPConnectionPool.initialConnections must be at least 1.");
    Validator.ensureTrue(maxConnections >= initialConnections,
         "LDAPConnectionPool.initialConnections must not be greater than " +
              "maxConnections.");

    // NOTE:  The post-connect processor (if any) will be used in the server
    // set that we create rather than in the connection pool itself.
    this.postConnectProcessor = null;

    trySynchronousReadDuringHealthCheck = true;
    healthCheckInterval       = DEFAULT_HEALTH_CHECK_INTERVAL;
    poolStatistics            = new LDAPConnectionPoolStatistics(this);
    pooledSchema              = null;
    connectionPoolName        = null;
    retryOperationTypes       = new AtomicReference<>(
         Collections.unmodifiableSet(EnumSet.noneOf(OperationType.class)));
    numConnections            = maxConnections;
    minConnectionGoal         = 0;
    availableConnections      = new LinkedBlockingQueue<>(numConnections);

    if (! connection.isConnected())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
                              ERR_POOL_CONN_NOT_ESTABLISHED.get());
    }

    if (healthCheck == null)
    {
      this.healthCheck = new LDAPConnectionPoolHealthCheck();
    }
    else
    {
      this.healthCheck = healthCheck;
    }


    bindRequest = connection.getLastBindRequest();
    serverSet = new SingleServerSet(connection.getConnectedAddress(),
                                    connection.getConnectedPort(),
                                    connection.getLastUsedSocketFactory(),
                                    connection.getConnectionOptions(), null,
                                    postConnectProcessor);

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

    final List<LDAPConnection> connList;
    if (initialConnectThreads > 1)
    {
      connList = Collections.synchronizedList(
           new ArrayList<LDAPConnection>(initialConnections));
      final ParallelPoolConnector connector = new ParallelPoolConnector(this,
           connList, initialConnections, initialConnectThreads,
           throwOnConnectFailure);
      connector.establishConnections();
    }
    else
    {
      connList = new ArrayList<>(initialConnections);
      connection.setConnectionName(null);
      connection.setConnectionPool(this);
      connList.add(connection);
      for (int i=1; i < initialConnections; i++)
      {
        try
        {
          connList.add(createConnection());
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);

          if (throwOnConnectFailure)
          {
            for (final LDAPConnection c : connList)
            {
              try
              {
                c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null,
                     le);
                c.setClosed();
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
              }
            }

            throw le;
          }
        }
      }
    }

    availableConnections.addAll(connList);

    failedReplaceCount                 =
         new AtomicInteger(maxConnections - availableConnections.size());
    createIfNecessary                  = true;
    checkConnectionAgeOnRelease        = false;
    maxConnectionAge                   = 0L;
    maxDefunctReplacementConnectionAge = null;
    minDisconnectInterval              = 0L;
    lastExpiredDisconnectTime          = 0L;
    maxWaitTime                        = 0L;
    closed                             = false;

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
   *                         performed on the connections.  Note that if the
   *                         server set is configured to perform
   *                         authentication, this bind request should be the
   *                         same bind request used by the server set.  This is
   *                         important because even though the server set may
   *                         be used to perform the initial authentication on a
   *                         newly established connection, this connection
   *                         pool may still need to re-authenticate the
   *                         connection.
   * @param  numConnections  The total number of connections that should be
   *                         created in the pool.  It must be greater than or
   *                         equal to one.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         any of the connections.  If this is thrown, then
   *                         all connections associated with the pool will be
   *                         closed.
   */
  public LDAPConnectionPool(@NotNull final ServerSet serverSet,
                            @Nullable final BindRequest bindRequest,
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
   *                             performed on the connections.  Note that if the
   *                             server set is configured to perform
   *                             authentication, this bind request should be the
   *                             same bind request used by the server set.
   *                             This is important because even though the
   *                             server set may be used to perform the initial
   *                             authentication on a newly established
   *                             connection, this connection pool may still
   *                             need to re-authenticate the connection.
   * @param  initialConnections  The number of connections to initially
   *                             establish when the pool is created.  It must be
   *                             greater than or equal to zero.
   * @param  maxConnections      The maximum number of connections that should
   *                             be maintained in the pool.  It must be greater
   *                             than or equal to the initial number of
   *                             connections, and must not be zero.  See the
   *                             "Pool Connection Management" section of the
   *                             class-level documentation for an explanation of
   *                             how the pool treats the maximum number of
   *                             connections.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         any of the connections.  If this is thrown, then
   *                         all connections associated with the pool will be
   *                         closed.
   */
  public LDAPConnectionPool(@NotNull final ServerSet serverSet,
                            @Nullable final BindRequest bindRequest,
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
   *                               performed on the connections.  Note that if
   *                               the server set is configured to perform
   *                               authentication, this bind request should be
   *                               the same bind request used by the server set.
   *                               This is important because even though the
   *                               server set may be used to perform the initial
   *                               authentication on a newly established
   *                               connection, this connection pool may still
   *                               need to re-authenticate the connection.
   * @param  initialConnections    The number of connections to initially
   *                               establish when the pool is created.  It must
   *                               be greater than or equal to zero.
   * @param  maxConnections        The maximum number of connections that should
   *                               be maintained in the pool.  It must be
   *                               greater than or equal to the initial number
   *                               of connections, and must not be zero.  See
   *                               the "Pool Connection Management" section of
   *                               the class-level documentation for an
   *                               explanation of how the pool treats the
   *                               maximum number of connections.
   * @param  postConnectProcessor  A processor that should be used to perform
   *                               any post-connect processing for connections
   *                               in this pool.  It may be {@code null} if no
   *                               special processing is needed.  Note that if
   *                               the server set is configured with a
   *                               non-{@code null} post-connect processor, then
   *                               the post-connect processor provided to the
   *                               pool must be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         any of the connections.  If this is thrown, then
   *                         all connections associated with the pool will be
   *                         closed.
   */
  public LDAPConnectionPool(@NotNull final ServerSet serverSet,
              @Nullable final BindRequest bindRequest,
              final int initialConnections, final int maxConnections,
              @Nullable final PostConnectProcessor postConnectProcessor)
         throws LDAPException
  {
    this(serverSet, bindRequest, initialConnections, maxConnections,
         postConnectProcessor, true);
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created using the provided server set.
   *
   * @param  serverSet              The server set to use to create the
   *                                connections.  It is acceptable for the
   *                                server set to create the connections across
   *                                multiple servers.
   * @param  bindRequest            The bind request to use to authenticate the
   *                                connections that are established.  It may be
   *                                {@code null} if no authentication should be
   *                                performed on the connections.  Note that if
   *                                the server set is configured to perform
   *                                authentication, this bind request should be
   *                                the same bind request used by the server
   *                                set.  This is important because even
   *                                though the server set may be used to
   *                                perform the initial authentication on a
   *                                newly established connection, this
   *                                connection pool may still need to
   *                                re-authenticate the connection.
   * @param  initialConnections     The number of connections to initially
   *                                establish when the pool is created.  It must
   *                                be greater than or equal to zero.
   * @param  maxConnections         The maximum number of connections that
   *                                should be maintained in the pool.  It must
   *                                be greater than or equal to the initial
   *                                number of connections, and must not be zero.
   *                                See the "Pool Connection Management" section
   *                                of the class-level documentation for an
   *                                explanation of how the pool treats the
   *                                maximum number of connections.
   * @param  postConnectProcessor   A processor that should be used to perform
   *                                any post-connect processing for connections
   *                                in this pool.  It may be {@code null} if no
   *                                special processing is needed.  Note that if
   *                                the server set is configured with a
   *                                non-{@code null} post-connect processor,
   *                                then the post-connect processor provided
   *                                to the pool must be {@code null}.
   * @param  throwOnConnectFailure  If an exception should be thrown if a
   *                                problem is encountered while attempting to
   *                                create the specified initial number of
   *                                connections.  If {@code true}, then the
   *                                attempt to create the pool will fail.if any
   *                                connection cannot be established.  If
   *                                {@code false}, then the pool will be created
   *                                but may have fewer than the initial number
   *                                of connections (or possibly no connections).
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         any of the connections and
   *                         {@code throwOnConnectFailure} is true.  If this is
   *                         thrown, then all connections associated with the
   *                         pool will be closed.
   */
  public LDAPConnectionPool(@NotNull final ServerSet serverSet,
              @Nullable final BindRequest bindRequest,
              final int initialConnections, final int maxConnections,
              @Nullable final PostConnectProcessor postConnectProcessor,
              final boolean throwOnConnectFailure)
         throws LDAPException
  {
    this(serverSet, bindRequest, initialConnections, maxConnections, 1,
         postConnectProcessor, throwOnConnectFailure);
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created using the provided server set.
   *
   * @param  serverSet              The server set to use to create the
   *                                connections.  It is acceptable for the
   *                                server set to create the connections across
   *                                multiple servers.
   * @param  bindRequest            The bind request to use to authenticate the
   *                                connections that are established.  It may be
   *                                {@code null} if no authentication should be
   *                                performed on the connections.  Note that if
   *                                the server set is configured to perform
   *                                authentication, this bind request should be
   *                                the same bind request used by the server
   *                                set.  This is important because even
   *                                though the server set may be used to
   *                                perform the initial authentication on a
   *                                newly established connection, this
   *                                connection pool may still need to
   *                                re-authenticate the connection.
   * @param  initialConnections     The number of connections to initially
   *                                establish when the pool is created.  It must
   *                                be greater than or equal to zero.
   * @param  maxConnections         The maximum number of connections that
   *                                should be maintained in the pool.  It must
   *                                be greater than or equal to the initial
   *                                number of connections, and must not be zero.
   *                                See the "Pool Connection Management" section
   *                                of the class-level documentation for an
   *                                explanation of how the pool treats the
   *                                maximum number of connections.
   * @param  initialConnectThreads  The number of concurrent threads to use to
   *                                establish the initial set of connections.
   *                                A value greater than one indicates that the
   *                                attempt to establish connections should be
   *                                parallelized.
   * @param  postConnectProcessor   A processor that should be used to perform
   *                                any post-connect processing for connections
   *                                in this pool.  It may be {@code null} if no
   *                                special processing is needed.  Note that if
   *                                the server set is configured with a
   *                                non-{@code null} post-connect processor,
   *                                then the post-connect processor provided
   *                                to the pool must be {@code null}.
   * @param  throwOnConnectFailure  If an exception should be thrown if a
   *                                problem is encountered while attempting to
   *                                create the specified initial number of
   *                                connections.  If {@code true}, then the
   *                                attempt to create the pool will fail.if any
   *                                connection cannot be established.  If
   *                                {@code false}, then the pool will be created
   *                                but may have fewer than the initial number
   *                                of connections (or possibly no connections).
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         any of the connections and
   *                         {@code throwOnConnectFailure} is true.  If this is
   *                         thrown, then all connections associated with the
   *                         pool will be closed.
   */
  public LDAPConnectionPool(@NotNull final ServerSet serverSet,
              @Nullable final BindRequest bindRequest,
              final int initialConnections, final int maxConnections,
              final int initialConnectThreads,
              @Nullable final PostConnectProcessor postConnectProcessor,
              final boolean throwOnConnectFailure)
         throws LDAPException
  {
    this(serverSet, bindRequest, initialConnections, maxConnections,
         initialConnectThreads, postConnectProcessor, throwOnConnectFailure,
         null);
  }



  /**
   * Creates a new LDAP connection pool with the specified number of
   * connections, created using the provided server set.
   *
   * @param  serverSet              The server set to use to create the
   *                                connections.  It is acceptable for the
   *                                server set to create the connections across
   *                                multiple servers.
   * @param  bindRequest            The bind request to use to authenticate the
   *                                connections that are established.  It may be
   *                                {@code null} if no authentication should be
   *                                performed on the connections.  Note that if
   *                                the server set is configured to perform
   *                                authentication, this bind request should be
   *                                the same bind request used by the server
   *                                set.  This is important because even
   *                                though the server set may be used to
   *                                perform the initial authentication on a
   *                                newly established connection, this
   *                                connection pool may still need to
   *                                re-authenticate the connection.
   * @param  initialConnections     The number of connections to initially
   *                                establish when the pool is created.  It must
   *                                be greater than or equal to zero.
   * @param  maxConnections         The maximum number of connections that
   *                                should be maintained in the pool.  It must
   *                                be greater than or equal to the initial
   *                                number of connections, and must not be zero.
   *                                See the "Pool Connection Management" section
   *                                of the class-level documentation for an
   *                                explanation of how the pool treats the
   *                                maximum number of connections.
   * @param  initialConnectThreads  The number of concurrent threads to use to
   *                                establish the initial set of connections.
   *                                A value greater than one indicates that the
   *                                attempt to establish connections should be
   *                                parallelized.
   * @param  postConnectProcessor   A processor that should be used to perform
   *                                any post-connect processing for connections
   *                                in this pool.  It may be {@code null} if no
   *                                special processing is needed.  Note that if
   *                                the server set is configured with a
   *                                non-{@code null} post-connect processor,
   *                                then the post-connect processor provided
   *                                to the pool must be {@code null}.
   * @param  throwOnConnectFailure  If an exception should be thrown if a
   *                                problem is encountered while attempting to
   *                                create the specified initial number of
   *                                connections.  If {@code true}, then the
   *                                attempt to create the pool will fail if any
   *                                connection cannot be established.  If
   *                                {@code false}, then the pool will be created
   *                                but may have fewer than the initial number
   *                                of connections (or possibly no connections).
   * @param  healthCheck            The health check that should be used for
   *                                connections in this pool.  It may be
   *                                {@code null} if the default health check
   *                                should be used.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         any of the connections and
   *                         {@code throwOnConnectFailure} is true.  If this is
   *                         thrown, then all connections associated with the
   *                         pool will be closed.
   */
  public LDAPConnectionPool(@NotNull final ServerSet serverSet,
              @Nullable final BindRequest bindRequest,
              final int initialConnections, final int maxConnections,
              final int initialConnectThreads,
              @Nullable final PostConnectProcessor postConnectProcessor,
              final boolean throwOnConnectFailure,
              @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    Validator.ensureNotNull(serverSet);
    Validator.ensureTrue(initialConnections >= 0,
         "LDAPConnectionPool.initialConnections must be greater than or " +
              "equal to 0.");
    Validator.ensureTrue(maxConnections > 0,
         "LDAPConnectionPool.maxConnections must be greater than 0.");
    Validator.ensureTrue(maxConnections >= initialConnections,
         "LDAPConnectionPool.initialConnections must not be greater than " +
              "maxConnections.");

    this.serverSet            = serverSet;
    this.bindRequest          = bindRequest;
    this.postConnectProcessor = postConnectProcessor;

    if (serverSet.includesAuthentication())
    {
      Validator.ensureTrue((bindRequest != null),
           "LDAPConnectionPool.bindRequest must not be null if " +
                "serverSet.includesAuthentication returns true");
    }

    if (serverSet.includesPostConnectProcessing())
    {
      Validator.ensureTrue((postConnectProcessor == null),
           "LDAPConnectionPool.postConnectProcessor must be null if " +
                "serverSet.includesPostConnectProcessing returns true.");
    }

    trySynchronousReadDuringHealthCheck = false;
    healthCheckInterval = DEFAULT_HEALTH_CHECK_INTERVAL;
    poolStatistics      = new LDAPConnectionPoolStatistics(this);
    pooledSchema        = null;
    connectionPoolName  = null;
    retryOperationTypes = new AtomicReference<>(
         Collections.unmodifiableSet(EnumSet.noneOf(OperationType.class)));
    minConnectionGoal   = 0;
    numConnections = maxConnections;
    availableConnections = new LinkedBlockingQueue<>(numConnections);

    if (healthCheck == null)
    {
      this.healthCheck = new LDAPConnectionPoolHealthCheck();
    }
    else
    {
      this.healthCheck = healthCheck;
    }

    final List<LDAPConnection> connList;
    if (initialConnectThreads > 1)
    {
      connList = Collections.synchronizedList(
           new ArrayList<LDAPConnection>(initialConnections));
      final ParallelPoolConnector connector = new ParallelPoolConnector(this,
           connList, initialConnections, initialConnectThreads,
           throwOnConnectFailure);
      connector.establishConnections();
    }
    else
    {
      connList = new ArrayList<>(initialConnections);
      for (int i=0; i < initialConnections; i++)
      {
        try
        {
          connList.add(createConnection());
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);

          if (throwOnConnectFailure)
          {
            for (final LDAPConnection c : connList)
            {
              try
              {
                c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null,
                     le);
                c.setClosed();
              } catch (final Exception e)
              {
                Debug.debugException(e);
              }
            }

            throw le;
          }
        }
      }
    }

    availableConnections.addAll(connList);

    failedReplaceCount                 =
         new AtomicInteger(maxConnections - availableConnections.size());
    createIfNecessary                  = true;
    checkConnectionAgeOnRelease        = false;
    maxConnectionAge                   = 0L;
    maxDefunctReplacementConnectionAge = null;
    minDisconnectInterval              = 0L;
    lastExpiredDisconnectTime          = 0L;
    maxWaitTime                        = 0L;
    closed                             = false;

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
  LDAPConnection createConnection()
                 throws LDAPException
  {
    return createConnection(healthCheck);
  }



  /**
   * Creates a new LDAP connection for use in this pool.
   *
   * @param  healthCheck  The health check to use to determine whether the
   *                      newly-created connection is valid.  It may be
   *                      {@code null} if no additional health checking should
   *                      be performed for the newly-created connection.
   *
   * @return  A new connection created for use in this pool.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         the connection.  If a connection had been created,
   *                         it will be closed.
   */
  @SuppressWarnings("deprecation")
  @NotNull()
  private LDAPConnection createConnection(
                @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
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
        if (healthCheck != null)
        {
          healthCheck.ensureConnectionValidAfterAuthentication(c, bindResult);
        }

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
             new ArrayList<>(availableConnections.size());
        availableConnections.drainTo(connList);

        if (! connList.isEmpty())
        {
          final ParallelPoolCloser closer =
               new ParallelPoolCloser(connList, unbind, numThreads);
          closer.closeConnections();
        }
      }
      else
      {
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
    if (closed)
    {
      poolStatistics.incrementNumFailedCheckouts();
      Debug.debugConnectionPool(Level.SEVERE, this, null,
           "Failed to get a connection to a closed connection pool", null);
      throw new LDAPException(ResultCode.CONNECT_ERROR,
                              ERR_POOL_CLOSED.get());
    }

    LDAPConnection conn = availableConnections.poll();
    if (conn != null)
    {
      Exception connException = null;
      if (conn.isConnected())
      {
        try
        {
          healthCheck.ensureConnectionValidForCheckout(conn);
          poolStatistics.incrementNumSuccessfulCheckoutsWithoutWaiting();
          Debug.debugConnectionPool(Level.INFO, this, conn,
               "Checked out an immediately available pooled connection", null);
          return conn;
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          connException = le;
        }
      }

      poolStatistics.incrementNumConnectionsClosedDefunct();
      Debug.debugConnectionPool(Level.WARNING, this, conn,
           "Closing a defunct connection encountered during checkout",
           connException);
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
            Debug.debugConnectionPool(Level.INFO, this, conn,
                 "Checked out an immediately available pooled connection",
                 null);
            return conn;
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            poolStatistics.incrementNumConnectionsClosedDefunct();
            Debug.debugConnectionPool(Level.WARNING, this, conn,
                 "Closing a defunct connection encountered during checkout",
                 le);
            handleDefunctConnection(conn);
          }
        }
        else
        {
          poolStatistics.incrementNumConnectionsClosedDefunct();
          Debug.debugConnectionPool(Level.WARNING, this, conn,
               "Closing a defunct connection encountered during checkout",
               null);
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
          Debug.debugConnectionPool(Level.INFO, this, conn,
               "Checked out a newly created connection", null);
          return conn;
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          failedReplaceCount.incrementAndGet();
          poolStatistics.incrementNumFailedCheckouts();
          Debug.debugConnectionPool(Level.SEVERE, this, conn,
               "Unable to create a new connection for checkout", le);
          throw le;
        }
      }
      else
      {
        failedReplaceCount.incrementAndGet();
      }
    }

    if (maxWaitTime > 0)
    {
      try
      {
        final long startWaitTime = System.currentTimeMillis();
        conn = availableConnections.poll(maxWaitTime, TimeUnit.MILLISECONDS);
        final long elapsedWaitTime = System.currentTimeMillis() - startWaitTime;
        if (conn != null)
        {
          try
          {
            healthCheck.ensureConnectionValidForCheckout(conn);
            poolStatistics.incrementNumSuccessfulCheckoutsAfterWaiting();
            Debug.debugConnectionPool(Level.INFO, this, conn,
                 "Checked out an existing connection after waiting " +
                      elapsedWaitTime + "ms for it to become available",
                 null);
            return conn;
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            poolStatistics.incrementNumConnectionsClosedDefunct();
            Debug.debugConnectionPool(Level.WARNING, this, conn,
                 "Got a connection for checkout after waiting " +
                      elapsedWaitTime + "ms for it to become available, but " +
                      "the connection failed the checkout health check",
                 le);
            handleDefunctConnection(conn);
          }
        }
      }
      catch (final InterruptedException ie)
      {
        Debug.debugException(ie);
        Thread.currentThread().interrupt();
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_POOL_CHECKOUT_INTERRUPTED.get(), ie);
      }
    }

    if (createIfNecessary)
    {
      try
      {
        conn = createConnection();
        poolStatistics.incrementNumSuccessfulCheckoutsNewConnection();
        Debug.debugConnectionPool(Level.INFO, this, conn,
             "Checked out a newly created connection", null);
        return conn;
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        poolStatistics.incrementNumFailedCheckouts();
        Debug.debugConnectionPool(Level.SEVERE, this, null,
             "Unable to create a new connection for checkout", le);
        throw le;
      }
    }
    else
    {
      poolStatistics.incrementNumFailedCheckouts();
      Debug.debugConnectionPool(Level.SEVERE, this, null,
           "Unable to check out a connection because none are available",
           null);
      throw new LDAPException(ResultCode.CONNECT_ERROR,
                              ERR_POOL_NO_CONNECTIONS.get());
    }
  }



  /**
   * Attempts to retrieve a connection from the pool that is established to the
   * specified server.  Note that this method will only attempt to return an
   * existing connection that is currently available, and will not create a
   * connection or wait for any checked-out connections to be returned.
   *
   * @param  host  The address of the server to which the desired connection
   *               should be established.  This must not be {@code null}, and
   *               this must exactly match the address provided for the initial
   *               connection or the {@code ServerSet} used to create the pool.
   * @param  port  The port of the server to which the desired connection should
   *               be established.
   *
   * @return  A connection that is established to the specified server, or
   *          {@code null} if there are no available connections established to
   *          the specified server.
   */
  @Nullable()
  public LDAPConnection getConnection(@NotNull final String host,
                                               final int port)
  {
    if (closed)
    {
      poolStatistics.incrementNumFailedCheckouts();
      Debug.debugConnectionPool(Level.WARNING, this, null,
           "Failed to get a connection to a closed connection pool", null);
      return null;
    }

    final HashSet<LDAPConnection> examinedConnections =
         new HashSet<>(StaticUtils.computeMapCapacity(numConnections));
    while (true)
    {
      final LDAPConnection conn = availableConnections.poll();
      if (conn == null)
      {
        poolStatistics.incrementNumFailedCheckouts();
        Debug.debugConnectionPool(Level.SEVERE, this, null,
             "Failed to get an existing connection to " + host + ':' + port +
                  " because no connections are immediately available",
             null);
        return null;
      }

      if (examinedConnections.contains(conn))
      {
        if (! availableConnections.offer(conn))
        {
          discardConnection(conn);
        }

        poolStatistics.incrementNumFailedCheckouts();
        Debug.debugConnectionPool(Level.WARNING, this, null,
             "Failed to get an existing connection to " + host + ':' + port +
                  " because none of the available connections are " +
                  "established to that server",
             null);
        return null;
      }

      if (conn.getConnectedAddress().equals(host) &&
          (port == conn.getConnectedPort()))
      {
        try
        {
          healthCheck.ensureConnectionValidForCheckout(conn);
          poolStatistics.incrementNumSuccessfulCheckoutsWithoutWaiting();
          Debug.debugConnectionPool(Level.INFO, this, conn,
               "Successfully checked out an existing connection to requested " +
                    "server " + host + ':' + port,
               null);
          return conn;
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          poolStatistics.incrementNumConnectionsClosedDefunct();
          Debug.debugConnectionPool(Level.WARNING, this, conn,
               "Closing an existing connection to requested server " + host +
                    ':' + port + " because it failed the checkout health " +
                    "check",
               le);
          handleDefunctConnection(conn);
          continue;
        }
      }

      if (availableConnections.offer(conn))
      {
        examinedConnections.add(conn);
      }
      else
      {
        discardConnection(conn);
      }
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
    if (checkConnectionAgeOnRelease && connectionIsExpired(connection))
    {
      try
      {
        final LDAPConnection newConnection = createConnection();
        if (availableConnections.offer(newConnection))
        {
          connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_EXPIRED,
               null, null);
          connection.terminate(null);
          poolStatistics.incrementNumConnectionsClosedExpired();
          Debug.debugConnectionPool(Level.WARNING, this, connection,
               "Closing a released connection because it is expired", null);
          lastExpiredDisconnectTime = System.currentTimeMillis();
        }
        else
        {
          newConnection.setDisconnectInfo(
               DisconnectType.POOLED_CONNECTION_UNNEEDED, null, null);
          newConnection.terminate(null);
          poolStatistics.incrementNumConnectionsClosedUnneeded();
          Debug.debugConnectionPool(Level.WARNING, this, connection,
               "Closing a released connection because the pool is already full",
               null);
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
      }
      return;
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

    if (availableConnections.offer(connection))
    {
      poolStatistics.incrementNumReleasedValid();
      Debug.debugConnectionPool(Level.INFO, this, connection,
           "Released a connection back to the pool", null);
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
      Debug.debugConnectionPool(Level.WARNING, this, connection,
           "Closing a released connection because the pool is already full",
           null);
      connection.terminate(null);
      return;
    }

    if (closed)
    {
      close();
    }
  }



  /**
   * Indicates that the provided connection should be removed from the pool,
   * and that no new connection should be created to take its place.  This may
   * be used to shrink the pool if such functionality is desired.
   *
   * @param  connection  The connection to be discarded.
   */
  public void discardConnection(@NotNull final LDAPConnection connection)
  {
    if (connection == null)
    {
      return;
    }

    connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
         null, null);
    connection.terminate(null);
    poolStatistics.incrementNumConnectionsClosedUnneeded();
    Debug.debugConnectionPool(Level.INFO, this, connection,
         "Discareded a connection that is no longer needed", null);

    if (availableConnections.remainingCapacity() > 0)
    {
      final int newReplaceCount = failedReplaceCount.incrementAndGet();
      if (newReplaceCount > numConnections)
      {
        failedReplaceCount.set(numConnections);
      }
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
          connection.setClosed();
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
   *
   * @return  The new connection created to take the place of the defunct
   *          connection, or {@code null} if no new connection was created.
   *          Note that if a connection is returned, it will have already been
   *          made available and the caller must not rely on it being unused for
   *          any other purpose.
   */
  @NotNull()
  private LDAPConnection handleDefunctConnection(
                              @NotNull final LDAPConnection connection)
  {
    connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, null,
                                 null);
    connection.setClosed();

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
      if (maxDefunctReplacementConnectionAge != null)
      {
        // Only set the maximum age if there isn't one already set for the
        // connection (i.e., because it was defined by the server set).
        if (conn.getAttachment(ATTACHMENT_NAME_MAX_CONNECTION_AGE) == null)
        {
          conn.setAttachment(ATTACHMENT_NAME_MAX_CONNECTION_AGE,
               maxDefunctReplacementConnectionAge);
        }
      }

      if (! availableConnections.offer(conn))
      {
        conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                               null, null);
        conn.terminate(null);
        return null;
      }

      return conn;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      final int newReplaceCount = failedReplaceCount.incrementAndGet();
      if (newReplaceCount > numConnections)
      {
        failedReplaceCount.set(numConnections);
      }
      return null;
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

    if (closed)
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR, ERR_POOL_CLOSED.get());
    }

    try
    {
      return createConnection();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      failedReplaceCount.incrementAndGet();
      throw le;
    }
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
    // There may be a custom maximum connection age for the connection.  If that
    // is the case, then use that custom max age rather than the pool-default
    // max age.
    final long maxAge;
    final Object maxAgeObj =
         connection.getAttachment(ATTACHMENT_NAME_MAX_CONNECTION_AGE);
    if ((maxAgeObj != null) && (maxAgeObj instanceof Long))
    {
      maxAge = (Long) maxAgeObj;
    }
    else
    {
      maxAge = maxConnectionAge;
    }

    // If connection expiration is not enabled, then there is nothing to do.
    if (maxAge <= 0L)
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
    return (connectionAge > maxAge);
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
  public void setServerSet(@Nullable final ServerSet serverSet)
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
   * Retrieves the maximum connection age that should be used for connections
   * that were created in order to replace defunct connections.  It is possible
   * to define a custom maximum connection age for these connections to allow
   * them to be closed and re-established more quickly to allow for a
   * potentially quicker fail-back to a normal state.  Note, that if this
   * capability is to be used, then the maximum age for these connections should
   * be long enough to allow the problematic server to become available again
   * under normal circumstances (e.g., it should be long enough for at least a
   * shutdown and restart of the server, plus some overhead for potentially
   * performing routine maintenance while the server is offline, or a chance for
   * an administrator to be made available that a server has gone down).
   *
   * @return  The maximum connection age that should be used for connections
   *          that were created in order to replace defunct connections, a value
   *          of zero to indicate that no maximum age should be enforced, or
   *          {@code null} if the value returned by the
   *          {@link #getMaxConnectionAgeMillis()} method should be used.
   */
  @Nullable()
  public Long getMaxDefunctReplacementConnectionAgeMillis()
  {
    return maxDefunctReplacementConnectionAge;
  }



  /**
   * Specifies the maximum connection age that should be used for connections
   * that were created in order to replace defunct connections.  It is possible
   * to define a custom maximum connection age for these connections to allow
   * them to be closed and re-established more quickly to allow for a
   * potentially quicker fail-back to a normal state.  Note, that if this
   * capability is to be used, then the maximum age for these connections should
   * be long enough to allow the problematic server to become available again
   * under normal circumstances (e.g., it should be long enough for at least a
   * shutdown and restart of the server, plus some overhead for potentially
   * performing routine maintenance while the server is offline, or a chance for
   * an administrator to be made available that a server has gone down).
   *
   * @param  maxDefunctReplacementConnectionAge  The maximum connection age that
   *              should be used for connections that were created in order to
   *              replace defunct connections.  It may be zero if no maximum age
   *              should be enforced for such connections, or it may be
   *              {@code null} if the value returned by the
   *              {@link #getMaxConnectionAgeMillis()} method should be used.
   */
  public void setMaxDefunctReplacementConnectionAgeMillis(
                   @Nullable final Long maxDefunctReplacementConnectionAge)
  {
    if (maxDefunctReplacementConnectionAge == null)
    {
      this.maxDefunctReplacementConnectionAge = null;
    }
    else if (maxDefunctReplacementConnectionAge > 0L)
    {
      this.maxDefunctReplacementConnectionAge =
           maxDefunctReplacementConnectionAge;
    }
    else
    {
      this.maxDefunctReplacementConnectionAge = 0L;
    }
  }



  /**
   * Indicates whether to check the age of a connection against the configured
   * maximum connection age whenever it is released to the pool.  By default,
   * connection age is evaluated in the background using the health check
   * thread, but it is also possible to configure the pool to additionally
   * examine the age of a connection when it is returned to the pool.
   * <BR><BR>
   * Performing connection age evaluation only in the background will ensure
   * that connections are only closed and re-established in a single-threaded
   * manner, which helps minimize the load against the target server, but only
   * checks connections that are not in use when the health check thread is
   * active.  If the pool is configured to also evaluate the connection age when
   * connections are returned to the pool, then it may help ensure that the
   * maximum connection age is honored more strictly for all connections, but
   * in busy applications may lead to cases in which multiple connections are
   * closed and re-established simultaneously, which may increase load against
   * the directory server.  The {@link #setMinDisconnectIntervalMillis(long)}
   * method may be used to help mitigate the potential performance impact of
   * closing and re-establishing multiple connections simultaneously.
   *
   * @return  {@code true} if the connection pool should check connection age in
   *          both the background health check thread and when connections are
   *          released to the pool, or {@code false} if the connection age
   *          should only be checked by the background health check thread.
   */
  public boolean checkConnectionAgeOnRelease()
  {
    return checkConnectionAgeOnRelease;
  }



  /**
   * Specifies whether to check the age of a connection against the configured
   * maximum connection age whenever it is released to the pool.  By default,
   * connection age is evaluated in the background using the health check
   * thread, but it is also possible to configure the pool to additionally
   * examine the age of a connection when it is returned to the pool.
   * <BR><BR>
   * Performing connection age evaluation only in the background will ensure
   * that connections are only closed and re-established in a single-threaded
   * manner, which helps minimize the load against the target server, but only
   * checks connections that are not in use when the health check thread is
   * active.  If the pool is configured to also evaluate the connection age when
   * connections are returned to the pool, then it may help ensure that the
   * maximum connection age is honored more strictly for all connections, but
   * in busy applications may lead to cases in which multiple connections are
   * closed and re-established simultaneously, which may increase load against
   * the directory server.  The {@link #setMinDisconnectIntervalMillis(long)}
   * method may be used to help mitigate the potential performance impact of
   * closing and re-establishing multiple connections simultaneously.
   *
   * @param  checkConnectionAgeOnRelease  If {@code true}, this indicates that
   *                                      the connection pool should check
   *                                      connection age in both the background
   *                                      health check thread and when
   *                                      connections are released to the pool.
   *                                      If {@code false}, this indicates that
   *                                      the connection pool should check
   *                                      connection age only in the background
   *                                      health check thread.
   */
  public void setCheckConnectionAgeOnRelease(
                   final boolean checkConnectionAgeOnRelease)
  {
    this.checkConnectionAgeOnRelease = checkConnectionAgeOnRelease;
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
   * Indicates whether health check processing for connections operating in
   * synchronous mode should include attempting to perform a read from each
   * connection with a very short timeout.  This can help detect unsolicited
   * responses and unexpected connection closures in a more timely manner.  This
   * will be ignored for connections not operating in synchronous mode.
   *
   * @return  {@code true} if health check processing for connections operating
   *          in synchronous mode should include a read attempt with a very
   *          short timeout, or {@code false} if not.
   */
  public boolean trySynchronousReadDuringHealthCheck()
  {
    return trySynchronousReadDuringHealthCheck;
  }



  /**
   * Specifies whether health check processing for connections operating in
   * synchronous mode should include attempting to perform a read from each
   * connection with a very short timeout.
   *
   * @param  trySynchronousReadDuringHealthCheck  Indicates whether health check
   *                                              processing for connections
   *                                              operating in synchronous mode
   *                                              should include attempting to
   *                                              perform a read from each
   *                                              connection with a very short
   *                                              timeout.
   */
  public void setTrySynchronousReadDuringHealthCheck(
                   final boolean trySynchronousReadDuringHealthCheck)
  {
    this.trySynchronousReadDuringHealthCheck =
         trySynchronousReadDuringHealthCheck;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void doHealthCheck()
  {
    invokeHealthCheck(null, true);
  }



  /**
   * Invokes a synchronous one-time health-check against the connections in this
   * pool that are not currently in use.  This will be independent of any
   * background health checking that may be automatically performed by the pool.
   *
   * @param  healthCheck         The health check to use.  If this is
   *                             {@code null}, then the pool's
   *                             currently-configured health check (if any) will
   *                             be used.  If this is {@code null} and there is
   *                             no health check configured for the pool, then
   *                             only a basic set of checks.
   * @param  checkForExpiration  Indicates whether to check to see if any
   *                             connections have been established for longer
   *                             than the maximum connection age.  If this is
   *                             {@code true} then any expired connections will
   *                             be closed and replaced with newly-established
   *                             connections.
   *
   * @return  An object with information about the result of the health check
   *          processing.
   */
  @NotNull()
  public LDAPConnectionPoolHealthCheckResult invokeHealthCheck(
              @Nullable final LDAPConnectionPoolHealthCheck healthCheck,
              final boolean checkForExpiration)
  {
    return invokeHealthCheck(healthCheck, checkForExpiration,
         checkForExpiration);
  }



  /**
   * Invokes a synchronous one-time health-check against the connections in this
   * pool that are not currently in use.  This will be independent of any
   * background health checking that may be automatically performed by the pool.
   *
   * @param  healthCheck             The health check to use.  If this is
   *                                 {@code null}, then the pool's
   *                                 currently-configured health check (if any)
   *                                 will be used.  If this is {@code null} and
   *                                 there is no health check configured for the
   *                                 pool, then only a basic set of checks.
   * @param  checkForExpiration      Indicates whether to check to see if any
   *                                 connections have been established for
   *                                 longer than the maximum connection age.  If
   *                                 this is {@code true} then any expired
   *                                 connections will be closed and replaced
   *                                 with newly-established connections.
   * @param  checkMinConnectionGoal  Indicates whether to check to see if the
   *                                 currently-available number of connections
   *                                 is less than the minimum available
   *                                 connection goal.  If this is {@code true}
   *                                 the minimum available connection goal is
   *                                 greater than zero, and the number of
   *                                 currently-available connections is less
   *                                 than the goal, then this method will
   *                                 attempt to create enough new connections to
   *                                 reach the goal.
   *
   * @return  An object with information about the result of the health check
   *          processing.
   */
  @NotNull()
  public LDAPConnectionPoolHealthCheckResult invokeHealthCheck(
              @Nullable final LDAPConnectionPoolHealthCheck healthCheck,
              final boolean checkForExpiration,
              final boolean checkMinConnectionGoal)
  {
    // Determine which health check to use.
    final LDAPConnectionPoolHealthCheck hc;
    if (healthCheck == null)
    {
      hc = this.healthCheck;
    }
    else
    {
      hc = healthCheck;
    }


    // Create a set used to hold connections that we've already examined.  If we
    // encounter the same connection twice, then we know that we don't need to
    // do any more work.
    final HashSet<LDAPConnection> examinedConnections =
         new HashSet<>(StaticUtils.computeMapCapacity(numConnections));
    int numExamined = 0;
    int numDefunct = 0;
    int numExpired = 0;

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
          Debug.debugConnectionPool(Level.INFO, this, conn,
               "Closing a connection that had just been health checked " +
                    "because the pool is now full", null);
          conn.terminate(null);
        }
        break;
      }

      numExamined++;
      if (! conn.isConnected())
      {
        numDefunct++;
        poolStatistics.incrementNumConnectionsClosedDefunct();
        Debug.debugConnectionPool(Level.WARNING, this, conn,
             "Closing a connection that was identified as not established " +
                  "during health check processing",
             null);
        conn = handleDefunctConnection(conn);
        if (conn != null)
        {
          examinedConnections.add(conn);
        }
      }
      else
      {
        if (checkForExpiration && connectionIsExpired(conn))
        {
          numExpired++;

          try
          {
            final LDAPConnection newConnection = createConnection();
            if (availableConnections.offer(newConnection))
            {
              examinedConnections.add(newConnection);
              conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_EXPIRED,
                   null, null);
              conn.terminate(null);
              poolStatistics.incrementNumConnectionsClosedExpired();
              Debug.debugConnectionPool(Level.INFO, this, conn,
                   "Closing a connection that was identified as expired " +
                        "during health check processing",
                   null);
              lastExpiredDisconnectTime = System.currentTimeMillis();
              continue;
            }
            else
            {
              newConnection.setDisconnectInfo(
                   DisconnectType.POOLED_CONNECTION_UNNEEDED, null, null);
              newConnection.terminate(null);
              poolStatistics.incrementNumConnectionsClosedUnneeded();
              Debug.debugConnectionPool(Level.INFO, this, newConnection,
                   "Closing a newly created connection created to replace " +
                        "an expired connection because the pool is already " +
                        "full",
                   null);
            }
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
          }
        }


        // If the connection is operating in synchronous mode, then try to read
        // a message on it using an extremely short timeout.  This can help
        // detect a connection closure or unsolicited notification in a more
        // timely manner than if we had to wait for the client code to try to
        // use the connection.
        if (trySynchronousReadDuringHealthCheck && conn.synchronousMode())
        {
          int previousTimeout = Integer.MIN_VALUE;
          Socket s = null;
          try
          {
            s = conn.getConnectionInternals(true).getSocket();
            previousTimeout = s.getSoTimeout();
            InternalSDKHelper.setSoTimeout(conn, 1);

            final LDAPResponse response = conn.readResponse(0);
            if (response instanceof ConnectionClosedResponse)
            {
              numDefunct++;
              conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                   ERR_POOL_HEALTH_CHECK_CONN_CLOSED.get(), null);
              poolStatistics.incrementNumConnectionsClosedDefunct();
              Debug.debugConnectionPool(Level.WARNING, this, conn,
                   "Closing existing connection discovered to be " +
                        "disconnected during health check processing",
                   null);
              conn = handleDefunctConnection(conn);
              if (conn != null)
              {
                examinedConnections.add(conn);
              }
              continue;
            }
            else if (response instanceof ExtendedResult)
            {
              // This means we got an unsolicited response.  It could be a
              // notice of disconnection, or it could be something else, but in
              // any case we'll send it to the connection's unsolicited
              // notification handler (if one is defined).
              final UnsolicitedNotificationHandler h = conn.
                   getConnectionOptions().getUnsolicitedNotificationHandler();
              if (h != null)
              {
                h.handleUnsolicitedNotification(conn,
                     (ExtendedResult) response);
              }
            }
            else if (response instanceof LDAPResult)
            {
              final LDAPResult r = (LDAPResult) response;
              if (r.getResultCode() == ResultCode.SERVER_DOWN)
              {
                numDefunct++;
                conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                     ERR_POOL_HEALTH_CHECK_CONN_CLOSED.get(), null);
                poolStatistics.incrementNumConnectionsClosedDefunct();
                Debug.debugConnectionPool(Level.WARNING, this, conn,
                     "Closing existing connection discovered to be invalid " +
                          "with result " + r + " during health check " +
                          "processing",
                     null);
                conn = handleDefunctConnection(conn);
                if (conn != null)
                {
                  examinedConnections.add(conn);
                }
                continue;
              }
            }
          }
          catch (final LDAPException le)
          {
            if (le.getResultCode() == ResultCode.TIMEOUT)
            {
              Debug.debugException(Level.FINEST, le);
            }
            else
            {
              Debug.debugException(le);
              numDefunct++;
              conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                   ERR_POOL_HEALTH_CHECK_READ_FAILURE.get(
                        StaticUtils.getExceptionMessage(le)), le);
              poolStatistics.incrementNumConnectionsClosedDefunct();
              Debug.debugConnectionPool(Level.WARNING, this, conn,
                   "Closing existing connection discovered to be invalid " +
                        "during health check processing",
                   le);
              conn = handleDefunctConnection(conn);
              if (conn != null)
              {
                examinedConnections.add(conn);
              }
              continue;
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            numDefunct++;
            conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                 ERR_POOL_HEALTH_CHECK_READ_FAILURE.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
            poolStatistics.incrementNumConnectionsClosedDefunct();
            Debug.debugConnectionPool(Level.SEVERE, this, conn,
                 "Closing existing connection discovered to be invalid " +
                      "with an unexpected exception type during health check " +
                      "processing",
                 e);
            conn = handleDefunctConnection(conn);
            if (conn != null)
            {
              examinedConnections.add(conn);
            }
            continue;
          }
          finally
          {
            if (previousTimeout != Integer.MIN_VALUE)
            {
              try
              {
                if (s != null)
                {
                  InternalSDKHelper.setSoTimeout(conn, previousTimeout);
                }
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                numDefunct++;
                conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                     null, e);
                poolStatistics.incrementNumConnectionsClosedDefunct();
                Debug.debugConnectionPool(Level.SEVERE, this, conn,
                     "Closing existing connection during health check " +
                          "processing because an error occurred while " +
                          "attempting to set the SO_TIMEOUT",
                     e);
                conn = handleDefunctConnection(conn);
                if (conn != null)
                {
                  examinedConnections.add(conn);
                }
                continue;
              }
            }
          }
        }

        try
        {
          hc.ensureConnectionValidForContinuedUse(conn);
          if (availableConnections.offer(conn))
          {
            examinedConnections.add(conn);
          }
          else
          {
            conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                                   null, null);
            poolStatistics.incrementNumConnectionsClosedUnneeded();
            Debug.debugConnectionPool(Level.INFO, this, conn,
                 "Closing existing connection that passed health check " +
                      "processing because the pool is already full",
                 null);
            conn.terminate(null);
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          numDefunct++;
          poolStatistics.incrementNumConnectionsClosedDefunct();
          Debug.debugConnectionPool(Level.WARNING, this, conn,
               "Closing existing connection that failed health check " +
                    "processing",
               e);
          conn = handleDefunctConnection(conn);
          if (conn != null)
          {
            examinedConnections.add(conn);
          }
        }
      }
    }

    if (checkMinConnectionGoal)
    {
      try
      {
        final int neededConnections =
             minConnectionGoal - availableConnections.size();
        for (int i=0; i < neededConnections; i++)
        {
          final LDAPConnection conn = createConnection(hc);
          if (! availableConnections.offer(conn))
          {
            conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                                   null, null);
            poolStatistics.incrementNumConnectionsClosedUnneeded();
            Debug.debugConnectionPool(Level.INFO, this, conn,
                 "Closing a new connection that was created during health " +
                      "check processing in achieve the minimum connection " +
                      "goal, but the pool had already become full after the " +
                      "connection was created",
                 null);
            conn.terminate(null);
            break;
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return new LDAPConnectionPoolHealthCheckResult(numExamined, numExpired,
         numDefunct);
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
   * Retrieves the goal for the minimum number of available connections that the
   * pool should try to maintain for immediate use.  If this goal is greater
   * than zero, then the health checking process will attempt to create enough
   * new connections to achieve this goal.
   *
   * @return  The goal for the minimum number of available connections that the
   *          pool should try to maintain for immediate use, or zero if it will
   *          not try to maintain a minimum number of available connections.
   */
  public int getMinimumAvailableConnectionGoal()
  {
    return minConnectionGoal;
  }



  /**
   * Specifies the goal for the minimum number of available connections that the
   * pool should try to maintain for immediate use.  If this goal is greater
   * than zero, then the health checking process will attempt to create enough
   * new connections to achieve this goal.
   *
   * @param  goal  The goal for the minimum number of available connections that
   *               the pool should try to maintain for immediate use.  A value
   *               less than or equal to zero indicates that the pool should not
   *               try to maintain a minimum number of available connections.
   */
  public void setMinimumAvailableConnectionGoal(final int goal)
  {
    if (goal > numConnections)
    {
      minConnectionGoal = numConnections;
    }
    else if (goal > 0)
    {
      minConnectionGoal = goal;
    }
    else
    {
      minConnectionGoal = 0;
    }
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
   * Attempts to reduce the number of connections available for use in the pool.
   * Note that this will be a best-effort attempt to reach the desired number
   * of connections, as other threads interacting with the connection pool may
   * check out and/or release connections that cause the number of available
   * connections to fluctuate.
   *
   * @param  connectionsToRetain  The number of connections that should be
   *                              retained for use in the connection pool.
   */
  public void shrinkPool(final int connectionsToRetain)
  {
    while (availableConnections.size() > connectionsToRetain)
    {
      final LDAPConnection conn;
      try
      {
        conn = getConnection();
      }
      catch (final LDAPException le)
      {
        return;
      }

      if (availableConnections.size() >= connectionsToRetain)
      {
        discardConnection(conn);
      }
      else
      {
        releaseConnection(conn);
        return;
      }
    }
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
