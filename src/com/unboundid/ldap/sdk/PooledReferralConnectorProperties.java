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



import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines a set of properties for use when creating a
 * {@link PooledReferralConnector}.  Changing any properties after a
 * connector is created will not cause any changes in the connector.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PooledReferralConnectorProperties
{
  // The bind request to use to authenticate to pooled connections, as an
  // alternative to the bind request used to authenticate connections on which
  // referrals were received.
  @Nullable private BindRequest bindRequest;

  // Indicates whether to retry operations on a newly established connection
  // if the initial attempt fails in a way that suggests that the pooled
  // connection may not be valid.
  private boolean retryFailedOperationsDueToInvalidConnections;

  // The initial number of connections to establish when creating a connection
  // pool.
  private int initialConnectionsPerPool;

  // The maximum number of connections to maintain in each of the connection
  // pools.
  private int maximumConnectionsPerPool;

  // The connection options to use when establishing new connections, as an
  // alternative to the connection options used for a connection on which a
  // referral was received.
  @Nullable private LDAPConnectionOptions connectionOptions;

  // A health check to use for the connection pools.
  @Nullable private LDAPConnectionPoolHealthCheck healthCheck;

  // The interval that the background thread should use when checking for
  // cleanup operations.
  private long backgroundThreadCheckIntervalMillis;

  // The health check interval in milliseconds to use for the connection pools.
  private long healthCheckIntervalMillis;

  // The maximum length of time in milliseconds that any individual pooled
  // connection should be allowed to remain established.
  private long maximumConnectionAgeMillis;

  // The maximum length of time in milliseconds that any connection pool should
  // be allowed to remain active.
  private long maximumPoolAgeMillis;

  // The maximum length of time in milliseconds that should be allowed to pass
  // since a connection pool was last used to follow a referral before it is
  // discarded.
  private long maximumPoolIdleDurationMillis;

  // The security type to use when establishing connections in response to
  // referral URLs with a scheme of "ldap".
  @NotNull private PooledReferralConnectorLDAPURLSecurityType
       ldapURLSecurityType;

  // The SSL socket factory to use when performing TLS negotiation, as an
  // alternative to the socket factory from the associated connection.
  @Nullable private SSLSocketFactory sslSocketFactory;



  /**
   * Creates a new set of pooled referral connector properties with the default
   * settings.
   */
  public PooledReferralConnectorProperties()
  {
    bindRequest = null;
    retryFailedOperationsDueToInvalidConnections = true;
    initialConnectionsPerPool = 1;
    maximumConnectionsPerPool = 10;
    connectionOptions = null;
    healthCheck = null;
    backgroundThreadCheckIntervalMillis = TimeUnit.SECONDS.toMillis(10L);
    healthCheckIntervalMillis = TimeUnit.MINUTES.toMillis(1L);
    maximumConnectionAgeMillis = TimeUnit.MINUTES.toMillis(30L);
    maximumPoolAgeMillis = 0L;
    maximumPoolIdleDurationMillis = TimeUnit.HOURS.toMillis(1L);
    ldapURLSecurityType = PooledReferralConnectorLDAPURLSecurityType.
         CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS;
    sslSocketFactory = null;
  }



  /**
   * Creates a new set of pooled referral connector properties that is a
   * duplicate of the provided set of properties.
   *
   * @param  properties  The set of properties to duplicate.  It must not be
   *                     {@code null}.
   */
  public PooledReferralConnectorProperties(
              @NotNull final PooledReferralConnectorProperties properties)
  {
    bindRequest = properties.bindRequest;
    retryFailedOperationsDueToInvalidConnections =
         properties.retryFailedOperationsDueToInvalidConnections;
    initialConnectionsPerPool = properties.initialConnectionsPerPool;
    maximumConnectionsPerPool = properties.maximumConnectionsPerPool;
    connectionOptions = properties.connectionOptions;
    healthCheck = properties.healthCheck;
    backgroundThreadCheckIntervalMillis =
         properties.backgroundThreadCheckIntervalMillis;
    healthCheckIntervalMillis = properties.healthCheckIntervalMillis;
    maximumConnectionAgeMillis = properties.maximumConnectionAgeMillis;
    maximumPoolAgeMillis = properties.maximumPoolAgeMillis;
    maximumPoolIdleDurationMillis = properties.maximumPoolIdleDurationMillis;
    ldapURLSecurityType = properties.ldapURLSecurityType;
    sslSocketFactory = properties.sslSocketFactory;
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
   * Specifies the initial number of connections to establish when creating a
   * new connection pool for the purpose of following referrals.  By default,
   * only a single connection will be established.
   *
   * @param  initialConnectionsPerPool
   *              The initial number of connections to establish when creating a
   *              new connection pool for the purpose of following referrals.
   *              It must be greater than or equal to 1, and the initial number
   *              of connections per pool must ultimately be less than or equal
   *              to the maximum number of connections per pool.
   */
  public void setInitialConnectionsPerPool(final int initialConnectionsPerPool)
  {
    Validator.ensureTrue((initialConnectionsPerPool >= 1),
         "PooledReferralConnectorProperties.initialConnectionsPerPool must " +
              "be greater than or equal to one.");

    this.initialConnectionsPerPool = initialConnectionsPerPool;
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
   * Specifies the maximum number of idle connections that the server should
   * maintain in each connection pool used for following referrals.  By default,
   * a maximum of ten connections will be retained.
   *
   * @param  maximumConnectionsPerPool
   *              The maximum number of idle connections that the server should
   *              maintain in each connection pool used for following referrals.
   *              It must be greater than or equal to 1, and the initial number
   *              of connections per pool must ultimately be less than or equal
   *              to the maximum number of connections per pool.
   */
  public void setMaximumConnectionsPerPool(final int maximumConnectionsPerPool)
  {
    Validator.ensureTrue((initialConnectionsPerPool >= 1),
         "PooledReferralConnectorProperties.maximumConnectionsPerPool must " +
              "be greater than or equal to one.");

    this.maximumConnectionsPerPool = maximumConnectionsPerPool;
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
   * Specifies whether the connection pools should be configured to
   * automatically retry an operation on a newly established connection if the
   * initial attempt fails in a manner that suggests that the connection may no
   * longer be valid.  By default, operations that fail in that manner will
   * automatically be retried.
   *
   * @param  retryFailedOperationsDueToInvalidConnections
   *              Indicates whether the connection pools should be configured to
   *              automatically retry an operation on a newly established
   *              connection if the initial attempt fails in a manner that
   *              suggests that the connection may no longer be valid.
   */
  public void setRetryFailedOperationsDueToInvalidConnections(
                   final boolean retryFailedOperationsDueToInvalidConnections)
  {
    this.retryFailedOperationsDueToInvalidConnections =
         retryFailedOperationsDueToInvalidConnections;
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
   * Specifies the maximum length of time in milliseconds that each pooled
   * connection may remain established.  If a pooled connection is established
   * for longer than this duration, it will be closed and re-established.  By
   * default, pooled connections will be allowed to remain established for up
   * to 30 minutes.  A value that is less than or equal to zero indicates that
   * pooled connections will be allowed to remain established indefinitely (or
   * at least until it is determined to be invalid or the pool is closed).
   *
   * @param  maximumConnectionAgeMillis
   *              The maximum length of time in milliseconds that each pooled
   *              connection may remain established.  A value that is less than
   *              or equal to zero indicates that pooled connections will be
   *              allowed to remain established indefinitely.
   */
  public void setMaximumConnectionAgeMillis(
                   final long maximumConnectionAgeMillis)
  {
    if (maximumConnectionAgeMillis > 0L)
    {
      this.maximumConnectionAgeMillis = maximumConnectionAgeMillis;
    }
    else
    {
      this.maximumConnectionAgeMillis = 0L;
    }
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
   * Specifies the maximum length of time in milliseconds that a connection pool
   * created for the purpose of following referrals should be retained,
   * regardless of how often it is used.  If it has been longer than this length
   * of time since a referral connection pool was created, it will be
   * automatically closed, and a new pool will be created if another applicable
   * referral is received.  A value that is less than or equal to zero (with the
   * default value being zero) indicates that connection pools should not be
   * automatically closed based on the length of time since they were created.
   *
   * @param  maximumPoolAgeMillis
   *              The maximum length of time in milliseconds that a referral
   *              connection pool should be retained.  A value that is less than
   *              or equal to zero indicates that connection pools should not be
   *              automatically closed based on their age.
   */
  public void setMaximumPoolAgeMillis(final long maximumPoolAgeMillis)
  {
    if (maximumPoolAgeMillis > 0L)
    {
      this.maximumPoolAgeMillis = maximumPoolAgeMillis;
    }
    else
    {
      this.maximumPoolAgeMillis = 0L;
    }
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
   * Specifies the maximum length of time in milliseconds that a connection pool
   * created for the purpose of following referrals should be retained after its
   * most recent use.  By default, referral connection pools will be
   * automatically discarded if they have remained unused for over one hour.  A
   * value of zero indicates that pools may remain in use indefinitely,
   * regardless of how long it has been since they were last used.
   *
   * @param  maximumPoolIdleDurationMillis
   *              The maximum length of time in milliseconds that a connection
   *              pool created for the purpose of following referrals should be
   *              retained after its most recent use.  A value that is less than
   *              or equal to zero indicates that connection pools should not be
   *              automatically closed based on how long it has been since they
   *              were last used.
   */
  public void setMaximumPoolIdleDurationMillis(
                   final long maximumPoolIdleDurationMillis)
  {
    if (maximumPoolIdleDurationMillis > 0L)
    {
      this.maximumPoolIdleDurationMillis = maximumPoolIdleDurationMillis;
    }
    else
    {
      this.maximumPoolIdleDurationMillis = 0L;
    }
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
   * Specifies the health check that should be used to determine whether pooled
   * connections are still valid.  By default, no special health checking will
   * be performed for pooled connections (aside from checking them against
   * the maximum connection age).
   *
   * @param  healthCheck
   *              The health check that should be used to determine whether
   *              pooled connections are still valid.  It may be {@code null} if
   *              no special health checking should be performed.
   */
  public void setHealthCheck(
                   @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
  {
    this.healthCheck = healthCheck;
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
   * Specifies the length of time in milliseconds between background health
   * checks performed against pooled connections.
   *
   * @param  healthCheckIntervalMillis
   *              The length of time in milliseconds between background health
   *              checks performed against pooled connections.  It must be
   *              greater than zero.
   */
  public void setHealthCheckIntervalMillis(
                   final long healthCheckIntervalMillis)
  {
    Validator.ensureTrue((healthCheckIntervalMillis > 0L),
         "PooledReferralConnectorProperties.healthCheckIntervalMillis must " +
              "be greater than zero.");

    this.healthCheckIntervalMillis = healthCheckIntervalMillis;
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
   * Specifies the bind request that should be used to authenticate pooled
   * connections.  By default, pooled connections will be authenticated with the
   * same bind request that was used to  authenticate the connection on which
   * the referral was received (with separate pools used for referrals received
   * on connections authenticated as different users)., but this method may be
   * used to override that and explicitly specify a bind request to use for
   * authenticating all pooled connections.
   *
   * @param  bindRequest
   *              The bind request that should be used to authenticate pooled
   *              connections.  It may be {@code null} if connections should be
   *              authenticated with the same bind request used to authenticate
   *              a connection on which a referral was received (with separate
   *              pools used for referrals received on connections authenticated
   *              as different users).
   */
  public void setBindRequest(@Nullable final BindRequest bindRequest)
  {
    this.bindRequest = bindRequest;
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
    if (connectionOptions == null)
    {
      return null;
    }
    else
    {
      return connectionOptions.duplicate();
    }
  }



  /**
   * Specifies the set of options that will be used when establishing new pooled
   * connections for the purpose of following referrals.  By default, new
   * connections will use the same set of options as the connection on which a
   * referral was received.
   *
   * @param  connectionOptions
   *              The set of options that will be used when establishing new
   *              pooled connections for the purpose of following referrals.  It
   *              may be {@code null} if new connections should use the same set
   *              of options as the connection on which a referral was received.
   */
  public void setConnectionOptions(
                   @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this.connectionOptions = connectionOptions;
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
   * Specifies the type of communication security that the referral connector
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
   * @param  ldapURLSecurityType
   *              The type of communication security that the referral connector
   *              should use when creating connections for referral URLs with a
   *              scheme of "ldap".  It must not be {@code null}.
   */
  public void setLDAPURLSecurityType(
                   @NotNull final PooledReferralConnectorLDAPURLSecurityType
                        ldapURLSecurityType)
  {
    Validator.ensureNotNullWithMessage(ldapURLSecurityType,
         "PooledReferralConnectorProperties.ldapURLSecurityType must not be " +
              "null.");

    this.ldapURLSecurityType = ldapURLSecurityType;
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
   * Specifies the SSL socket factory that will be used when performing TLS
   * negotiation on any new connections created for the purpose of following
   * referrals.  By default, new pooled connections will use the same socket
   * factory as the connection on which a referral was received.
   *
   * @param  sslSocketFactory
   *              The SSL socket factory that will be used when performing TLS
   *              negotiation on any new connections created for the purpose of
   *              following referrals.  It may be {@code null} if new pooled
   *              connections should use the same socket factory as the
   *              connection on which a referral was received.
   */
  public void setSSLSocketFactory(
                   @Nullable final SSLSocketFactory sslSocketFactory)
  {
    this.sslSocketFactory = sslSocketFactory;
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
   * Specifies the interval duration in milliseconds that the
   * {@link PooledReferralConnectorBackgroundThread} should use when sleeping
   * between checks to determine if any of the established referral connection
   * pools should be closed.  This is only intended for internal use.  By
   * default, the interval duration will be 10 seconds (10,000 milliseconds).
   *
   * @param  backgroundThreadCheckIntervalMillis
   *              The interval duration in milliseconds that the
   *              {@code PooledReferralConnectorBackgroundThread} should use
   *              when sleeping between checks.  The value must be greater than
   *              zero.
   */
  void setBackgroundThreadCheckIntervalMillis(
            final long backgroundThreadCheckIntervalMillis)
  {
    this.backgroundThreadCheckIntervalMillis =
         backgroundThreadCheckIntervalMillis;
  }



  /**
   * Retrieves a string representation of the pooled referral connector
   * properties.
   *
   * @return  A string representation of the pooled referral connector
   *          properties.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of the pooled referral connector properties
   * to the provided buffer.
   *
   * @param  buffer
   *              The buffer to which the string representation should be
   *              appended.  It must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PooledReferralConnectionProperties(" +
         "initialConnectionsPerPool=");
    buffer.append(initialConnectionsPerPool);
    buffer.append(", maximumConnectionsPerPool=");
    buffer.append(maximumConnectionsPerPool);
    buffer.append(", retryFailedOperationsDueToInvalidConnections=");
    buffer.append(retryFailedOperationsDueToInvalidConnections);
    buffer.append(", maximumConnectionAgeMillis=");
    buffer.append(maximumConnectionAgeMillis);
    buffer.append(", maximumPoolAgeMillis=");
    buffer.append(maximumPoolAgeMillis);
    buffer.append(", maximumPoolIdleDurationMillis=");
    buffer.append(maximumPoolIdleDurationMillis);
    buffer.append(", maximumPoolIdleDurationMillis=");
    buffer.append(maximumPoolIdleDurationMillis);
    buffer.append(", healthCheck=");
    buffer.append(healthCheck);
    buffer.append(", healthCheckIntervalMillis=");
    buffer.append(healthCheckIntervalMillis);
    buffer.append(", bindRequest=");
    buffer.append(bindRequest);
    buffer.append(", connectionOptions=");
    buffer.append(connectionOptions);
    buffer.append(", ldapURLSecurityType=");
    buffer.append(ldapURLSecurityType);
    buffer.append(", sslSocketFactory=");
    buffer.append(sslSocketFactory);
    buffer.append(')');
  }
}
