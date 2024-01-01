/*
 * Copyright 2023-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023-2024 Ping Identity Corporation
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
 * Copyright (C) 2023-2024 Ping Identity Corporation
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



import java.util.concurrent.atomic.AtomicReference;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.Validator;
import com.unboundid.util.ssl.AggregateTrustManager;
import com.unboundid.util.ssl.SSLUtil;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure with a connection pool and other
 * associated information that may be used in the course of following referrals.
 */
final class ReferralConnectionPool
{
  // The time that the connection pool was last used in the course of following
  // a referral.
  @NotNull private final AtomicReference<Long> lastUsedTimeMillisRef;

  // Indicates whether we need to check the authentication ID when determining
  // whether this pool is applicable to a referral.
  private final boolean checkAuthenticationID;

  // The port of the server to which connections are established.
  private final int serverPort;

  // The connection pool that may be used when following referrals;
  @NotNull private final LDAPConnectionPool connectionPool;

  // The time that the connection pool was created.
  private final long poolCreateTimeMillis;

  // The associated pooled referral connector.
  @NotNull private final PooledReferralConnector referralConnector;

  // The address of the server to which the connections are established.
  @NotNull private final String serverAddress;

  // An identifier that is used to reference the user that is authenticated
  // on the pooled connections.
  @Nullable private final String authenticationIdentifier;



  /**
   * Creates a new referral connection pool from the provided information.
   *
   * @param  referralURL        The LDAP URL for a referral that was received.
   *                            It must not be {@code null}.
   * @param  connection         The LDAP connection on which the referral was
   *                            received.  It must not be {@code null}.
   * @param  referralConnector  The associated pooled referral connector.  It
   *                            must not be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to create the
   *                         connection pool.
   */
  ReferralConnectionPool(@NotNull final LDAPURL referralURL,
       @NotNull final LDAPConnection connection,
       @NotNull final PooledReferralConnector referralConnector)
       throws LDAPException
  {
    this.referralConnector = referralConnector;

    serverAddress = referralURL.getHost();
    serverPort = referralURL.getPort();

    BindRequest bindRequest = referralConnector.getBindRequest();
    if (bindRequest == null)
    {
      bindRequest = connection.getLastBindRequest();
      checkAuthenticationID = true;
      if (bindRequest == null)
      {
        authenticationIdentifier = "";
      }
      else
      {
        authenticationIdentifier = getAuthenticationIdentifier(connection);
        if (authenticationIdentifier == null)
        {
          final String authenticationType = "SASL " +
               ((SASLBindRequest) bindRequest).getSASLMechanismName();
          throw new LDAPException(ResultCode.AUTH_METHOD_NOT_SUPPORTED,
               ERR_REFERRAL_POOL_UNSUPPORTED_BIND_TYPE.get(authenticationType));
        }
      }
    }
    else
    {
      authenticationIdentifier = null;
      checkAuthenticationID = false;
    }


    final SocketFactory socketFactory =
         getSocketFactory(referralURL, connection);
    final LDAPConnectionOptions connectionOptions =
         getConnectionOptions(connection);
    final PostConnectProcessor postConnectProcessor =
         getPostConnectProcessor(referralURL, connection);

    final SingleServerSet serverSet = new SingleServerSet(serverAddress,
         serverPort, socketFactory, connectionOptions, bindRequest,
         postConnectProcessor);

    connectionPool = new LDAPConnectionPool(serverSet, bindRequest,
         referralConnector.getInitialConnectionsPerPool(),
         referralConnector.getMaximumConnectionsPerPool(),
         1, null, false, referralConnector.getHealthCheck());

    connectionPool.setRetryFailedOperationsDueToInvalidConnections(
         referralConnector.retryFailedOperationsDueToInvalidConnections());
    connectionPool.setHealthCheckIntervalMillis(
         referralConnector.getHealthCheckIntervalMillis());
    connectionPool.setMaxConnectionAgeMillis(
         referralConnector.getMaximumConnectionAgeMillis());

    poolCreateTimeMillis = System.currentTimeMillis();
    lastUsedTimeMillisRef = new AtomicReference<>(poolCreateTimeMillis);
  }



  /**
   * Retrieves the socket factory that should be used to establish connections
   * to the server that is the target for the referral.
   *
   * @param  referralURL  The LDAP URL for a referral that was received.  It
   *                      must not be {@code null}.
   * @param  connection   The LDAP connection on which the referral was
   *                      received.  It must not be {@code null}.
     *
   * @return  The socket factory that should be used to establish connections
   *          to the server that is the target for the referral.
   *
   * @throws  LDAPException  If a problem occurs while attempting to obtain the
   *                         socket factory to use to establish connections.
   */
  @NotNull()
  private SocketFactory getSocketFactory(
               @NotNull final LDAPURL referralURL,
               @NotNull final LDAPConnection connection)
          throws LDAPException

  {
    if (useLDAPS(referralURL, connection))
    {
      return getSSLSocketFactory(connection);
    }
    else
    {
      final SocketFactory connectionSocketFactory =
           connection.getSocketFactory();
      if (! (connectionSocketFactory instanceof SSLSocketFactory))
      {
        return connectionSocketFactory;
      }

      return SocketFactory.getDefault();
    }
  }



  /**
   * Indicates whether connections used to follow the specified referral should
   * be secured with LDAPS.
   *
   * @param  referralURL  The LDAP URL for a referral that was received.  It
   *                      must not be {@code null}.
   * @param  connection   The LDAP connection on which the referral was
   *                      received.  It must not be {@code null}.
   *
   * @return  {@code true} if referral connections should be secured with LDAPS,
   *          or {@code false} if not.
   */
  private boolean useLDAPS(@NotNull final LDAPURL referralURL,
                           @NotNull final LDAPConnection connection)
  {
    if (referralURL.getScheme().equalsIgnoreCase("ldaps"))
    {
      return true;
    }
    else
    {
      switch (referralConnector.getLDAPURLSecurityType())
      {
        case ALWAYS_USE_LDAPS:
          return true;

        case ALWAYS_USE_LDAP_AND_NEVER_USE_START_TLS:
        case ALWAYS_USE_LDAP_AND_ALWAYS_USE_START_TLS:
        case ALWAYS_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS:
          return false;

        case CONDITIONALLY_USE_LDAP_AND_NEVER_USE_START_TLS:
        case CONDITIONALLY_USE_LDAP_AND_ALWAYS_USE_START_TLS:
        case CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS:
          final SocketFactory socketFactory = connection.getSocketFactory();
          return (socketFactory instanceof SSLSocketFactory);

        default:
          Validator.violation("Unrecognized ldapURLSecurityType value '" +
               referralConnector.getLDAPURLSecurityType().name() + "'.");
          return false;
      }
    }
  }



  /**
   * Indicates whether connections used to follow the specified referral should
   * be secured with StartTLS.
   *
   * @param  referralURL  The LDAP URL for a referral that was received.  It
   *                      must not be {@code null}.
   * @param  connection   The LDAP connection on which the referral was
   *                      received.  It must not be {@code null}.
   *
   * @return  {@code true} if referral connections should be secured with LDAPS,
   *          or {@code false} if not.
   */
  private boolean useStartTLS(@NotNull final LDAPURL referralURL,
                              @NotNull final LDAPConnection connection)
  {
    if (referralURL.getScheme().equalsIgnoreCase("ldaps"))
    {
      return false;
    }
    else
    {
      switch (referralConnector.getLDAPURLSecurityType())
      {
        case ALWAYS_USE_LDAPS:
          return false;

        case ALWAYS_USE_LDAP_AND_NEVER_USE_START_TLS:
        case CONDITIONALLY_USE_LDAP_AND_NEVER_USE_START_TLS:
          return false;

        case ALWAYS_USE_LDAP_AND_ALWAYS_USE_START_TLS:
          return true;

        case ALWAYS_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS:
        case CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS:
          return (connection.getStartTLSRequest() != null);

        case CONDITIONALLY_USE_LDAP_AND_ALWAYS_USE_START_TLS:
          final SocketFactory socketFactory = connection.getSocketFactory();
          return (! (socketFactory instanceof SSLSocketFactory));

        default:
          Validator.violation("Unrecognized ldapURLSecurityType value '" +
               referralConnector.getLDAPURLSecurityType().name() + "'.");
          return false;
      }
    }
  }



  /**
   * Retrieves the SSL socket factory that should be used when performing TLS
   * negotiation.
   *
   * @param  connection  The LDAP connection on which the referral was
   *                     received.  It must not be {@code null}.
   *
   * @return  The SSL socket factory that should be used when performing TLS
   *          negotiation.
   *
   * @throws  LDAPException  If a problem occurs while attempting to obtain the
   *                         SSL socket factory.
   */
  @NotNull()
  private SSLSocketFactory getSSLSocketFactory(
                                @NotNull final LDAPConnection connection)
          throws LDAPException
  {
    final SSLSocketFactory explicitlyConfiguredSSLSocketFactory =
         referralConnector.getSSLSocketFactory();
    if (explicitlyConfiguredSSLSocketFactory != null)
    {
      return explicitlyConfiguredSSLSocketFactory;
    }

    final SocketFactory connectionSocketFactory =
         connection.getSocketFactory();
    if (connectionSocketFactory instanceof SSLSocketFactory)
    {
      return (SSLSocketFactory) connectionSocketFactory;
    }


    final ExtendedRequest startTLSRequest = connection.getStartTLSRequest();
    if ((startTLSRequest != null) &&
         (startTLSRequest instanceof StartTLSExtendedRequest))
    {
      return ((StartTLSExtendedRequest) startTLSRequest).getSSLSocketFactory();
    }

    final AggregateTrustManager preferredTrustManagerChain =
         InternalSDKHelper.getPreferredNonInteractiveTrustManagerChain();
    final SSLUtil sslUtil = new SSLUtil(preferredTrustManagerChain);
    try
    {
      return sslUtil.createSSLSocketFactory();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_REFERRAL_POOL_CANNOT_CREATE_SSL_SOCKET_FACTORY.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the set of LDAP connection options that should be used when
   * establishing new connections.
   *
   * @param  connection  The LDAP connection on which the referral was
   *                     received.  It must not be {@code null}.
   *
   * @return  The set of LDAP connection options that should be used when
   *          establishing new connections.
   */
  @NotNull()
  private LDAPConnectionOptions getConnectionOptions(
               @NotNull final LDAPConnection connection)
  {
    final LDAPConnectionOptions poolConnectionOptions;
    final LDAPConnectionOptions explicitlyConfiguredConnectionOptions =
         referralConnector.getConnectionOptions();
    if (explicitlyConfiguredConnectionOptions != null)
    {
      poolConnectionOptions = explicitlyConfiguredConnectionOptions.duplicate();
    }
    else
    {
      poolConnectionOptions = connection.getConnectionOptions().duplicate();
    }

    // We don't want referral connections themselves to automatically follow any
    // referrals they encounter, so explicitly disable that.
    poolConnectionOptions.setFollowReferrals(false);
    poolConnectionOptions.setReferralConnector(null);

    return poolConnectionOptions;
  }



  /**
   * Retrieves the post-connect processor that should be used when creating
   * new connections, if any.
   *
   * @param  referralURL  The LDAP URL for a referral that was received.  It
   *                      must not be {@code null}.
   * @param  connection   The LDAP connection on which the referral was
   *                      received.  It must not be {@code null}.
   *
   * @return  The post-connect processor that should be used when creating new
   *          connections, or {@code null} if no post-connect processor is
   *          needed.
   *
   * @throws  LDAPException  If a problem occurs while attempting to create the
   *                         post-connect processor.
   */
  @Nullable()
  private PostConnectProcessor getPostConnectProcessor(
                                    @NotNull final LDAPURL referralURL,
                                    @NotNull final LDAPConnection connection)
          throws LDAPException
  {
    // We will only use a post-connect processor if connections are to be
    // secured with StartTLS.  If that's not the case, then return null;
    if (useStartTLS(referralURL, connection))
    {
      return new StartTLSPostConnectProcessor(getSSLSocketFactory(connection));
    }
    else
    {
      return null;
    }
  }



  /**
   * Closes the connection pool.
   */
  void close()
  {
    connectionPool.close();
  }



  /**
   * Indicates whether this referral connection pool is applicable for use in
   * following a referral with the provided information.
   *
   * @param  referralURL  The referral URL for which to make the determination.
   *                      It must not be {@code null}.
   * @param  connection   The connection on which the referral was received.  It
   *                      must not be {@code null}.
   *
   * @return  {@code true} if this connection pool is applicable for use with
   *          the provided referral URL, or {@code false} if not.
   */
  boolean isApplicableToReferral(@NotNull final LDAPURL referralURL,
                                 @NotNull final LDAPConnection connection)
  {
    if (! serverAddress.equals(referralURL.getHost()))
    {
      return false;
    }

    if (serverPort != referralURL.getPort())
    {
      return false;
    }

    if ((checkAuthenticationID) &&
         (! authenticationIdentifier.equals(
              getAuthenticationIdentifier(connection))))
    {
      return false;
    }

    return true;
  }



  /**
   * Retrieves a string that identifies the user that is authenticated on the
   * provided connection, if possible.
   *
   * @param  connection  The connection for which to retrieve an authentication
   *                     identifier.  It must not be {@code null}.
   *
   * @return  A string that identifies the user that is authenticated on the
   *          provided connection, or {@code null} if no identifier can be
   *          determined (e.g., because the associated authentication mechanism
   *          is not supported).
   */
  @Nullable()
  private static String getAuthenticationIdentifier(
               @NotNull final LDAPConnection connection)
  {
    final BindRequest bindRequest = connection.getLastBindRequest();
    if (bindRequest == null)
    {
      return "";
    }
    else if (bindRequest instanceof SimpleBindRequest)
    {
      final SimpleBindRequest simpleBindRequest =
           (SimpleBindRequest) bindRequest;
      try
      {
        return "dn:" + DN.normalize(simpleBindRequest.getBindDN());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        return simpleBindRequest.getBindDN();
      }
    }
    else if (bindRequest instanceof PLAINBindRequest)
    {
      final PLAINBindRequest plainBindRequest = (PLAINBindRequest) bindRequest;
      if (plainBindRequest.getAuthorizationID() == null)
      {
        return getAuthenticationIdentifier(
             plainBindRequest.getAuthenticationID());
      }
      else
      {
        return getAuthenticationIdentifier(
             plainBindRequest.getAuthorizationID());
      }
    }
    else if (bindRequest instanceof SCRAMBindRequest)
    {
      final SCRAMBindRequest scramBindRequest = (SCRAMBindRequest) bindRequest;
      return getAuthenticationIdentifier(scramBindRequest.getUsername());
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves an authentication identifier from the provided string.
   *
   * @param  id  The string from which to construct the authentication
   *             identifier.  It must not be {@code null}.
   *
   * @return  The authentication identifier that was created from the provided
   *          string.
   */
  @NotNull()
  private static String getAuthenticationIdentifier(@NotNull final String id)
  {
    if (id.startsWith("dn:"))
    {
      final String dnString = id.substring(3);
      try
      {
        return "dn:" + new DN(dnString).toNormalizedString();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return id;
  }



  /**
   * Retrieves the associated LDAP connection pool.
   *
   * @return  The associated connection pool.
   */
  @NotNull()
  LDAPConnectionPool getConnectionPool()
  {
    return connectionPool;
  }



  /**
   * Retrieves the time that the connection pool was created, in milliseconds
   * since the epoch.
   *
   * @return  The time that the connection pool was created.
   */
  long getPoolCreateTimeMillis()
  {
    return poolCreateTimeMillis;
  }



  /**
   * Retrieves the time that this connection pool was last used in the course
   * of following a referral, in milliseconds since the epoch.
   *
   * @return  The time that this connection pool was last used in the course
   *          of following a referral.  If the pool has never been used to
   *          follow a referral, then the time it was created will be returned
   *          instead.
   */
  long getLastUsedTimeMillis()
  {
    return lastUsedTimeMillisRef.get();
  }
}
