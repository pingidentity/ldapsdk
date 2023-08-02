/*
 * Copyright 2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023 Ping Identity Corporation
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
 * Copyright (C) 2023 Ping Identity Corporation
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



import java.io.Closeable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides an implementation of a reusable referral connector that
 * maintains pools of connections to each of the servers accessed in the course
 * of following referrals.  Connections may be reused across multiple
 * referrals.  Note that it is important to close the connector when it is no
 * longer needed, as that will ensure that all of the connection pools that it
 * maintains will be closed.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for establishing an LDAP
 * connection that will use this connector for following any referrals that are
 * encountered during processing:
 * <PRE>
 *   PooledReferralConnectorProperties properties =
 *        new PooledReferralConnectorProperties();
 *
 *   PooledReferralConnector referralConnector =
 *        new PooledReferralConnector(properties);
 *
 *   LDAPConnectionOptions options = new LDAPConnectionOptions();
 *   options.setFollowReferrals(true);
 *   options.setReferralConnector(referralConnector);
 *
 *   try (LDAPConnection conn = new LDAPConnection(socketFactory, options,
 *             serverAddress, serverPort)
 *   {
 *     // Use the connection to perform whatever processing is needed that might
 *     // involve receiving referrals.
 *   }
 *   finally
 *   {
 *     referralConnector.close();
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PooledReferralConnector
       implements ReusableReferralConnector, Closeable
{
  // Indicates whether a request has been made to close the connector.
  @NotNull private final AtomicBoolean closeRequested;

  // The bind request to use to authenticate to pooled connections, as an
  // alternative to the bind request used to authenticate connections on which
  // referrals were received.
  @Nullable private final BindRequest bindRequest;

  // Indicates whether to retry operations on a newlye established connection
  // if the initial attempt fails in a way that suggests that the pooled
  // connection may not be valid.
  private final boolean retryFailedOperationsDueToInvalidConnections;

  // The initial number of connections to establish when creating a connection
  // pool.
  private final int initialConnectionsPerPool;

  // The maximum number of connections to maintain in each of the connection
  // pools.
  private final int maximumConnectionsPerPool;

  // The connection options to use when establishing new connections, as an
  // alternative to the connection options used for a connection on which a
  // referral was received.
  @Nullable private final LDAPConnectionOptions connectionOptions;

  // A health check to use for the connection pools.
  @Nullable private final LDAPConnectionPoolHealthCheck healthCheck;

  // The interval that the background thread should use when checking for
  // cleanup operations.
  private final long backgroundThreadCheckIntervalMillis;

  // The health check interval in milliseconds to use for the connection pools.
  private final long healthCheckIntervalMillis;

  // The maximum length of time in milliseconds that any individual pooled
  // connection should be allowed to remain established.
  private final long maximumConnectionAgeMillis;

  // The maximum length of time in milliseconds that any connection pool should
  // be allowed to remain active.
  private final long maximumPoolAgeMillis;

  // The maximum length of time in milliseconds that should be allowed to pass
  // since a connection pool was last used to follow a referral before it is
  // discarded.
  private final long maximumPoolIdleDurationMillis;

  // The map of connection pools that have been created for this referral
  // connector, indexed by the address and port of the target server.
  @NotNull private final Map<String,List<ReferralConnectionPool>>
       poolsByHostPort;

  // The background thread that will monitor the set of pools to determine
  // whether any of them should be destroyed.
  @Nullable private final PooledReferralConnectorBackgroundThread
       backgroundThread;

  // The security type to use when establishing connections in response to
  // referral URLs with a scheme of "ldap".
  @NotNull private final PooledReferralConnectorLDAPURLSecurityType
       ldapURLSecurityType;

  // The SSL socket factory to use when performing TLS negotiation, as an
  // alternative to the socket factory from the associated connection.
  @Nullable private final SSLSocketFactory sslSocketFactory;



  /**
   * Creates a new pooled referral connector with a default set of properties.
   */
  public PooledReferralConnector()
  {
    this(new PooledReferralConnectorProperties());
  }



  /**
   * Creates a new pooled referral connector with the provided set of
   * properties.
   *
   * @param  properties  The properties to use for the pooled referral
   *                     connector.  It must not be {@code null}.
   */
  public PooledReferralConnector(
              @NotNull final PooledReferralConnectorProperties properties)
  {
    bindRequest = properties.getBindRequest();
    retryFailedOperationsDueToInvalidConnections =
         properties.retryFailedOperationsDueToInvalidConnections();
    initialConnectionsPerPool = properties.getInitialConnectionsPerPool();
    maximumConnectionsPerPool = properties.getMaximumConnectionsPerPool();
    connectionOptions = properties.getConnectionOptions();
    healthCheck = properties.getHealthCheck();
    backgroundThreadCheckIntervalMillis =
         properties.getBackgroundThreadCheckIntervalMillis();
    healthCheckIntervalMillis = properties.getHealthCheckIntervalMillis();
    maximumConnectionAgeMillis = properties.getMaximumConnectionAgeMillis();
    maximumPoolAgeMillis = properties.getMaximumPoolAgeMillis();
    maximumPoolIdleDurationMillis =
         properties.getMaximumPoolIdleDurationMillis();
    ldapURLSecurityType = properties.getLDAPURLSecurityType();
    sslSocketFactory = properties.getSSLSocketFactory();

    closeRequested = new AtomicBoolean(false);
    poolsByHostPort = new ConcurrentHashMap<>();

    if ((maximumPoolAgeMillis > 0L) || (maximumPoolIdleDurationMillis > 0L))
    {
      backgroundThread = new PooledReferralConnectorBackgroundThread(this);
      backgroundThread.start();
    }
    else
    {
      backgroundThread = null;
    }
  }



  /**
   * Retrieves the initial number of connections to establish when creating a
   * new connection pool for the purpose of following referrals.  By default,
   * only a single connection will be established.
   *
   * @return  The initial number of connections to establish when creating a
   *          new connection pool for the purpose of following referrals.
   */
  public int getInitialConnectionsPerPool()
  {
    return initialConnectionsPerPool;
  }



  /**
   * Retrieves the maximum number of idle connections that the server should
   * maintain in each connection pool used for following referrals.  By default,
   * a maximum of ten connections will be retained.
   *
   * @return  The maximum number of idle connections that the server should
   *          maintain in each connection pool used for following referrals.
   */
  public int getMaximumConnectionsPerPool()
  {
    return maximumConnectionsPerPool;
  }



  /**
   * Indicates whether the connection pools should be configured to
   * automatically retry an operation on a newly established connection if the
   * initial attempt fails in a manner that suggests that the connection may no
   * longer be valid.  By default, operations that fail in that manner will
   * automatically be retried.
   *
   * @return  {@code true} if connection pools should be configured to
   *          automatically retry an operation on a newly established connection
   *          if the initial attempt fails in a manner that suggests the
   *          connection may no longer be valid, or {@code false} if not.
   */
  public boolean retryFailedOperationsDueToInvalidConnections()
  {
    return retryFailedOperationsDueToInvalidConnections;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that each pooled
   * connection may remain established.  If a pooled connection is established
   * for longer than this duration, it will be closed and re-established.  By
   * default, pooled connections will be allowed to remain established for up
   * to 30 minutes.  A value of zero indicates that pooled connections will be
   * allowed to remain established indefinitely (or at least until it is
   * determined to be invalid or the pool is closed).
   *
   * @return  The maximum length of time in milliseconds that each pooled
   *          connection may remain established.
   */
  public long getMaximumConnectionAgeMillis()
  {
    return maximumConnectionAgeMillis;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that a connection pool
   * created for the purpose of following referrals should be retained,
   * regardless of how often it is used.  If it has been longer than this length
   * of time since a referral connection pool was created, it will be
   * automatically closed, and a new pool will be created if another applicable
   * referral is received.  A value of zero, which is the default, indicates
   * that connection pools should not be automatically closed based on the
   * length of time since they were created.
   *
   * @return  The maximum length of time in milliseconds that a referral
   *          connection pool should be retained, or zero if connection pools
   *          should not be automatically closed based on the length of time
   *          since they were created.
   */
  public long getMaximumPoolAgeMillis()
  {
    return maximumPoolAgeMillis;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that a connection pool
   * created for the purpose of following referrals should be retained after its
   * most recent use.  By default, referral connection pools will be
   * automatically discarded if they have remained unused for over one hour.  A
   * value of zero indicates that pools may remain in use indefinitely,
   * regardless of how long it has been since they were last used.
   *
   * @return  The maximum length of time in milliseconds that a connection pool
   *          created for the purpose of following referrals should be retained
   *          after its most recent use, or zero if referral connection pools
   *          should not be discarded regardless of how long it has been since
   *          they were last used.
   */
  public long getMaximumPoolIdleDurationMillis()
  {
    return maximumPoolIdleDurationMillis;
  }



  /**
   * Retrieves the health check that should be used to determine whether pooled
   * connections are still valid.  By default, no special health checking will
   * be performed for pooled connections (aside from checking them against
   * the maximum connection age).
   *
   * @return  The health check that should be used to determine whether pooled
   *          connections are still valid, or {@code null} if no special
   *          health checking should be performed.
   */
  @Nullable()
  public LDAPConnectionPoolHealthCheck getHealthCheck()
  {
    return healthCheck;
  }



  /**
   * Retrieves the length of time in milliseconds between background health
   * checks performed against pooled connections.  By default, background health
   * checks will be performed every sixty seconds.
   *
   * @return  The length of time in milliseconds between background health
   *          checks performed against pooled connections.
   */
  public long getHealthCheckIntervalMillis()
  {
    return healthCheckIntervalMillis;
  }



  /**
   * Retrieves the bind request that should be used to authenticate pooled
   * connections, if defined.  By default, pooled connections will be
   * authenticated with the same bind request that was used to authenticate
   * the connection on which the referral was received (with separate pools used
   * for referrals received on connections authenticated as different users).
   *
   * @return  The bind request that should be used to authenticate pooled
   *          connections, or {@code null} if pooled connections should be
   *          authenticated with the same bind request that was used to
   *          authenticate the connection on which the referral was received.
   */
  @Nullable()
  public BindRequest getBindRequest()
  {
    return bindRequest;
  }



  /**
   * Retrieves the set of options that will be used when establishing new pooled
   * connections for the purpose of following referrals.  By default, new
   * connections will use the same set of options as the connection on which a
   * referral was received.
   *
   * @return  The set of options that will be used when establishing new
   *          pooled connections for the purpose of following referrals, or
   *          {@code null} if new connections will use the same set of options
   *          as the connection on which a referral was received.
   */
  @Nullable()
  public LDAPConnectionOptions getConnectionOptions()
  {
    return connectionOptions;
  }



  /**
   * Indicates the type of communication security that the referral connector
   * should use when creating connections for referral URLs with a scheme of
   * "ldap".  Although the connector will always use LDAPS for connections
   * created from referral URLs with a scheme of "ldaps", the determination of
   * which security type to use for referral URLs with a scheme of "ldap" is
   * more complicated because the official LDAP URL specification lists "ldap"
   * as the only allowed scheme type.  See the class-level and value-level
   * documentation in the {@link PooledReferralConnectorLDAPURLSecurityType}
   * enum for more information.  By default, the
   * {@code CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS} security
   * type will be used.
   *
   * @return  The type of communication security that the referral connector
   *          should use when creating connections for referral URLs with a
   *          scheme of "ldap".
   */
  @NotNull()
  public PooledReferralConnectorLDAPURLSecurityType getLDAPURLSecurityType()
  {
    return ldapURLSecurityType;
  }



  /**
   * Retrieves the SSL socket factory that will be used when performing TLS
   * negotiation on any new connections created for the purpose of following
   * referrals.  By default, new pooled connections will use the same socket
   * factory as the connection on which a referral was received.
   *
   * @return  The SSL socket factory that will be used when performing TLS
   *          negotiation on any new connections created for the purpose of
   *          following referrals, or {@code null} if new pooled connections
   *          will use the same socket factory as the connection on which a
   *          referral was received.
   */
  @Nullable()
  public SSLSocketFactory getSSLSocketFactory()
  {
    return sslSocketFactory;
  }



  /**
   * Retrieves the interval duration in milliseconds that the
   * {@link PooledReferralConnectorBackgroundThread} should use when sleeping
   * between checks to determine if any of the established referral connection
   * pools should be closed.  This is only intended for internal use.  By
   * default, the interval duration will be 10 seconds (10,000 milliseconds).
   *
   * @return  The interval duration in milliseconds that the
   *          {@code PooledReferralConnectorBackgroundThread} should use when
   *          sleeping between checks.
   */
  long getBackgroundThreadCheckIntervalMillis()
  {
    return backgroundThreadCheckIntervalMillis;
  }



  /**
   * Closes and discards all connection pools that are associated with this
   * connector.  The connector will be unusable after it is closed.
   */
  public void close()
  {
    if (backgroundThread != null)
    {
      backgroundThread.shutDown();
    }

    synchronized (poolsByHostPort)
    {
      closeRequested.set(true);

      final Iterator<Map.Entry<String,List<ReferralConnectionPool>>> iterator =
           poolsByHostPort.entrySet().iterator();
      while (iterator.hasNext())
      {
        final Map.Entry<String,List<ReferralConnectionPool>> e =
             iterator.next();
        iterator.remove();

        for (final ReferralConnectionPool pool : e.getValue())
        {
          pool.close();
        }
      }
    }
  }



  /**
   * Retrieves the map of connection pools that have been created for the
   * purpose of following referrals.  This is for internal use only, and the
   * caller must synchronize on the returned map for any access to it.
   *
   * @return  The map of connection pools that have been created for the
   *          purpose of following referrals.
   */
  @NotNull()
  Map<String,List<ReferralConnectionPool>> getPoolsByHostPort()
  {
    return poolsByHostPort;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnectionPool getReferralInterface(
              @NotNull final LDAPURL referralURL,
              @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    final String hostPort = StaticUtils.toLowerCase(referralURL.getHost()) +
         ":" + referralURL.getPort();

    synchronized (poolsByHostPort)
    {
      if (closeRequested.get())
      {
        throw new LDAPException(ResultCode.UNAVAILABLE,
             ERR_POOLED_REFERRAL_CONNECTOR_CLOSED.get(
                  String.valueOf(referralURL)));
      }

      List<ReferralConnectionPool> pools = poolsByHostPort.get(hostPort);
      if (pools == null)
      {
        pools = new ArrayList<>();
        poolsByHostPort.put(hostPort, pools);
      }

      for (final ReferralConnectionPool pool : pools)
      {
        if (pool.isApplicableToReferral(referralURL, connection))
        {
          return pool.getConnectionPool();
        }
      }

      final ReferralConnectionPool newPool =
           new ReferralConnectionPool(referralURL, connection, this);
      pools.add(newPool);
      return newPool.getConnectionPool();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnection getReferralConnection(
              @NotNull final LDAPURL referralURL,
              @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    final LDAPConnectionPool connectionPool =
         getReferralInterface(referralURL, connection);
    return connectionPool.getConnection();
  }
}
