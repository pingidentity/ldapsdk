/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.security.auth.x500.X500Principal;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides a simple interface for creating {@code SSLContext} and
 * {@code SSLSocketFactory} instances, which may be used to create SSL-based
 * connections, or secure existing connections with StartTLS.  By default, only
 * the TLSv1.2 and TLSv1.3 (if supported by the JVM) will be enabled, with the
 * higher protocol version being the default and preferred for use.  The TLSv1.1
 * or TLSv1 protocol will only be enabled if the JVM does not support either
 * TLSv1.2 or TLSv1.3.
 * <BR><BR>
 * <H2>Example 1</H2>
 * The following example demonstrates the use of the SSL helper to create an
 * SSL-based LDAP connection that will blindly trust any certificate that the
 * server presents.  Using the {@code TrustAllTrustManager} is only recommended
 * for testing purposes, since blindly trusting any certificate is not secure.
 * <PRE>
 * // Create an SSLUtil instance that is configured to trust any certificate,
 * // and use it to create a socket factory.
 * SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
 * SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();
 *
 * // Establish a secure connection using the socket factory.
 * LDAPConnection connection = new LDAPConnection(sslSocketFactory);
 * connection.connect(serverAddress, serverSSLPort);
 *
 * // Process operations using the connection....
 * RootDSE rootDSE = connection.getRootDSE();
 *
 * connection.close();
 * </PRE>
 * <BR>
 * <H2>Example 2</H2>
 * The following example demonstrates the use of the SSL helper to create a
 * non-secure LDAP connection and then use the StartTLS extended operation to
 * secure it.  It will use a trust store to determine whether to trust the
 * server certificate.
 * <PRE>
 * // Establish a non-secure connection to the server.
 * LDAPConnection connection = new LDAPConnection(serverAddress, serverPort);
 *
 * // Create an SSLUtil instance that is configured to trust certificates in
 * // a specified trust store file, and use it to create an SSLContext that
 * // will be used for StartTLS processing.
 * SSLUtil sslUtil = new SSLUtil(new TrustStoreTrustManager(trustStorePath));
 * SSLContext sslContext = sslUtil.createSSLContext();
 *
 * // Use the StartTLS extended operation to secure the connection.
 * StartTLSExtendedRequest startTLSRequest =
 *      new StartTLSExtendedRequest(sslContext);
 * ExtendedResult startTLSResult;
 * try
 * {
 *   startTLSResult = connection.processExtendedOperation(startTLSRequest);
 * }
 * catch (LDAPException le)
 * {
 *   startTLSResult = new ExtendedResult(le);
 * }
 * LDAPTestUtils.assertResultCodeEquals(startTLSResult, ResultCode.SUCCESS);
 *
 * // Process operations using the connection....
 * RootDSE rootDSE = connection.getRootDSE();
 *
 * connection.close();
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SSLUtil
{
  /**
   * The name of a system property
   * (com.unboundid.util.SSLUtil.defaultSSLProtocol) that can be used to specify
   * the initial value for the default SSL protocol that should be used.  If
   * this is not set, then the default SSL protocol will be dynamically
   * determined.  This can be overridden via the
   * {@link #setDefaultSSLProtocol(String)} method.
   */
  @NotNull public static final String PROPERTY_DEFAULT_SSL_PROTOCOL =
       "com.unboundid.util.SSLUtil.defaultSSLProtocol";



  /**
   * The name of a system property
   * (com.unboundid.util.SSLUtil.enabledSSLProtocols) that can be used to
   * provide the initial set of enabled SSL protocols that should be used, as a
   * comma-delimited list.  If this is not set, then the enabled SSL protocols
   * will be dynamically determined.  This can be overridden via the
   * {@link #setEnabledSSLProtocols(Collection)} method.
   */
  @NotNull public static final String PROPERTY_ENABLED_SSL_PROTOCOLS =
       "com.unboundid.util.SSLUtil.enabledSSLProtocols";



  /**
   * The name of a system property
   * (com.unboundid.util.SSLUtil.enabledSSLCipherSuites) that can be used to
   * provide the initial set of enabled SSL cipher suites that should be used,
   * as a comma-delimited list.  If this is not set, then the enabled SSL cipher
   * suites will be dynamically determined using the
   * {@link TLSCipherSuiteSelector}.  This can be overridden via the
   * {@link #setEnabledSSLCipherSuites(Collection)} method.
   */
  @NotNull public static final String PROPERTY_ENABLED_SSL_CIPHER_SUITES =
       "com.unboundid.util.SSLUtil.enabledSSLCipherSuites";



  /**
   * The name of the SSL protocol that can be used to request TLSv1.3.
   */
  @NotNull public static final String SSL_PROTOCOL_TLS_1_3 = "TLSv1.3";



  /**
   * The name of the SSL protocol that can be used to request TLSv1.2.
   */
  @NotNull public static final String SSL_PROTOCOL_TLS_1_2 = "TLSv1.2";



  /**
   * The name of the SSL protocol that can be used to request TLSv1.1.
   */
  @NotNull public static final String SSL_PROTOCOL_TLS_1_1 = "TLSv1.1";



  /**
   * The name of the SSL protocol that can be used to request TLSv1.
   */
  @NotNull public static final String SSL_PROTOCOL_TLS_1 = "TLSv1";



  /**
   * The name of the SSL protocol that can be used to request SSLv3.
   */
  @NotNull public static final String SSL_PROTOCOL_SSL_3 = "SSLv3";



  /**
   * The name of the SSL protocol that can be used to request SSLv2Hello.
   */
  @NotNull public static final String SSL_PROTOCOL_SSL_2_HELLO = "SSLv2Hello";



  /**
   * The default protocol string that will be used to create SSL contexts when
   * no explicit protocol is specified.
   */
  @NotNull private static final AtomicReference<String> DEFAULT_SSL_PROTOCOL =
       new AtomicReference<>(SSL_PROTOCOL_TLS_1_2);



  /**
   * The default set of SSL cipher suites that will be enabled for use if
   * available for SSL sockets created within the LDAP SDK.
   */
  @NotNull private static final AtomicReference<Set<String>>
       ENABLED_SSL_CIPHER_SUITES = new AtomicReference<>(
            (Set<String>) new LinkedHashSet<>(
                 TLSCipherSuiteSelector.getDefaultCipherSuites()));



  /**
   * The default set of SSL protocols that will be enabled for use if available
   * for SSL sockets created within the LDAP SDK.
   */
  @NotNull private static final AtomicReference<Set<String>>
       ENABLED_SSL_PROTOCOLS = new AtomicReference<>(
            StaticUtils.setOf(SSL_PROTOCOL_TLS_1_2));



  static
  {
    configureSSLDefaults();
  }



  // The set of key managers to be used.
  @Nullable private final KeyManager[] keyManagers;

  // The set of trust managers to be used.
  @Nullable private final TrustManager[] trustManagers;



  /**
   * Creates a new SSLUtil instance that will not have a custom key manager or
   * trust manager.  It will not be able to provide a certificate to the server
   * if one is requested, and it will only trust certificates signed by a
   * predefined set of authorities.
   */
  public SSLUtil()
  {
    keyManagers   = null;
    trustManagers = null;
  }



  /**
   * Creates a new SSLUtil instance that will use the provided trust manager to
   * determine whether to trust server certificates presented to the client.
   * It will not be able to provide a certificate to the server if one is
   * requested.
   *
   * @param  trustManager  The trust manager to use to determine whether to
   *                       trust server certificates presented to the client.
   *                       It may be {@code null} if the default set of trust
   *                       managers should be used.
   */
  public SSLUtil(@Nullable final TrustManager trustManager)
  {
    keyManagers = null;

    if (trustManager == null)
    {
      trustManagers = null;
    }
    else
    {
      trustManagers = new TrustManager[] { trustManager };
    }
  }



  /**
   * Creates a new SSLUtil instance that will use the provided trust managers
   * to determine whether to trust server certificates presented to the client.
   * It will not be able to provide a certificate to the server if one is
   * requested.
   *
   * @param  trustManagers  The set of trust managers to use to determine
   *                        whether to trust server certificates presented to
   *                        the client.  It may be {@code null} or empty if the
   *                        default set of trust managers should be used.
   */
  public SSLUtil(@Nullable final TrustManager[] trustManagers)
  {
    keyManagers = null;

    if ((trustManagers == null) || (trustManagers.length == 0))
    {
      this.trustManagers = null;
    }
    else
    {
      this.trustManagers = trustManagers;
    }
  }



  /**
   * Creates a new SSLUtil instance that will use the provided key manager to
   * obtain certificates to present to the server, and the provided trust
   * manager to determine whether to trust server certificates presented to the
   * client.
   *
   * @param  keyManager    The key manager to use to obtain certificates to
   *                       present to the server if requested.  It may be
   *                       {@code null} if no client certificates will be
   *                       required or should be provided.
   * @param  trustManager  The trust manager to use to determine whether to
   *                       trust server certificates presented to the client.
   *                       It may be {@code null} if the default set of trust
   *                       managers should be used.
   */
  public SSLUtil(@Nullable final KeyManager keyManager,
                 @Nullable final TrustManager trustManager)
  {
    if (keyManager == null)
    {
      keyManagers = null;
    }
    else
    {
      keyManagers = new KeyManager[] { keyManager };
    }

    if (trustManager == null)
    {
      trustManagers = null;
    }
    else
    {
      trustManagers = new TrustManager[] { trustManager };
    }
  }



  /**
   * Creates a new SSLUtil instance that will use the provided key managers to
   * obtain certificates to present to the server, and the provided trust
   * managers to determine whether to trust server certificates presented to the
   * client.
   *
   * @param  keyManagers    The set of key managers to use to obtain
   *                        certificates to present to the server if requested.
   *                        It may be {@code null} or empty if no client
   *                        certificates will be required or should be provided.
   * @param  trustManagers  The set of trust managers to use to determine
   *                        whether to trust server certificates presented to
   *                        the client.  It may be {@code null} or empty if the
   *                        default set of trust managers should be used.
   */
  public SSLUtil(@Nullable final KeyManager[] keyManagers,
                 @Nullable final TrustManager[] trustManagers)
  {
    if ((keyManagers == null) || (keyManagers.length == 0))
    {
      this.keyManagers = null;
    }
    else
    {
      this.keyManagers = keyManagers;
    }

    if ((trustManagers == null) || (trustManagers.length == 0))
    {
      this.trustManagers = null;
    }
    else
    {
      this.trustManagers = trustManagers;
    }
  }



  /**
   * Retrieves the set of key managers configured for use by this class, if any.
   *
   * @return  The set of key managers configured for use by this class, or
   *          {@code null} if none were provided.
   */
  @Nullable()
  public KeyManager[] getKeyManagers()
  {
    return keyManagers;
  }



  /**
   * Retrieves the set of trust managers configured for use by this class, if
   * any.
   *
   * @return  The set of trust managers configured for use by this class, or
   *          {@code null} if none were provided.
   */
  @Nullable()
  public TrustManager[] getTrustManagers()
  {
    return trustManagers;
  }



  /**
   * Creates an initialized SSL context created with the configured key and
   * trust managers.  It will use the protocol returned by the
   * {@link #getDefaultSSLProtocol} method and the JVM-default provider.
   *
   * @return  The created SSL context.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL context.
   */
  @NotNull()
  public SSLContext createSSLContext()
         throws GeneralSecurityException
  {
    return createSSLContext(DEFAULT_SSL_PROTOCOL.get());
  }



  /**
   * Creates an initialized SSL context created with the configured key and
   * trust managers.  It will use a default provider.
   *
   * @param  protocol  The SSL protocol to use.  The Java Secure Socket
   *                   Extension (JSSE) Reference Guide provides a list of the
   *                   supported protocols, but commonly used values are
   *                   "TLSv1.3", "TLSv1.2", "TLSv1.1", and "TLSv1".  This must
   *                   not be {@code null}.
   *
   *
   * @return  The created SSL context.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL context.
   */
  @NotNull()
  public SSLContext createSSLContext(@NotNull final String protocol)
         throws GeneralSecurityException
  {
    Validator.ensureNotNull(protocol);

    final SSLContext sslContext = CryptoHelper.getSSLContext(protocol);
    sslContext.init(keyManagers, trustManagers, null);
    return sslContext;
  }



  /**
   * Creates an initialized SSL context created with the configured key and
   * trust managers.
   *
   * @param  protocol  The SSL protocol to use.  The Java Secure Socket
   *                   Extension (JSSE) Reference Guide provides a list of the
   *                   supported protocols, but commonly used values are
   *                   "TLSv1.3", "TLSv1.2", "TLSv1.1", and "TLSv1".  This must
   *                   not be {@code null}.
   * @param  provider  The name of the provider to use for cryptographic
   *                   operations.  It must not be {@code null}.
   *
   * @return  The created SSL context.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL context.
   */
  @NotNull()
  public SSLContext createSSLContext(@NotNull final String protocol,
                                     @NotNull final String provider)
         throws GeneralSecurityException
  {
    Validator.ensureNotNull(protocol, provider);

    final SSLContext sslContext =
         CryptoHelper.getSSLContext(protocol, provider);
    sslContext.init(keyManagers, trustManagers, null);
    return sslContext;
  }



  /**
   * Creates an SSL socket factory using the configured key and trust manager
   * providers.  It will use the protocol returned by the
   * {@link #getDefaultSSLProtocol} method and the JVM-default provider.
   *
   * @return  The created SSL socket factory.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL socket factory.
   */
  @NotNull()
  public SSLSocketFactory createSSLSocketFactory()
         throws GeneralSecurityException
  {
    return new SetEnabledProtocolsAndCipherSuitesSSLSocketFactory(
         createSSLContext().getSocketFactory(),
         ENABLED_SSL_PROTOCOLS.get(), ENABLED_SSL_CIPHER_SUITES.get());
  }



  /**
   * Creates an SSL socket factory with the configured key and trust managers.
   * It will use the default provider.
   *
   * @param  protocol  The SSL protocol to use.  The Java Secure Socket
   *                   Extension (JSSE) Reference Guide provides a list of the
   *                   supported protocols, but commonly used values are
   *                   "TLSv1.3", "TLSv1.2", "TLSv1.1", and "TLSv1".  This must
   *                   not be {@code null}.
   *
   * @return  The created SSL socket factory.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL socket factory.
   */
  @NotNull()
  public SSLSocketFactory createSSLSocketFactory(
                               @NotNull final String protocol)
         throws GeneralSecurityException
  {
    return new SetEnabledProtocolsAndCipherSuitesSSLSocketFactory(
         createSSLContext(protocol).getSocketFactory(), protocol,
         ENABLED_SSL_CIPHER_SUITES.get());
  }



  /**
   * Creates an SSL socket factory with the configured key and trust managers.
   *
   * @param  protocol  The SSL protocol to use.  The Java Secure Socket
   *                   Extension (JSSE) Reference Guide provides a list of the
   *                   supported protocols, but commonly used values are
   *                   "TLSv1.3", "TLSv1.2", "TLSv1.1", and "TLSv1".  This must
   *                   not be {@code null}.
   * @param  provider  The name of the provider to use for cryptographic
   *                   operations.  It must not be {@code null}.
   *
   * @return  The created SSL socket factory.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL socket factory.
   */
  @NotNull()
  public SSLSocketFactory createSSLSocketFactory(@NotNull final String protocol,
                                                 @NotNull final String provider)
         throws GeneralSecurityException
  {
    return createSSLContext(protocol, provider).getSocketFactory();
  }



  /**
   * Creates an SSL server socket factory using the configured key and trust
   * manager providers.  It will use the protocol returned by the
   * {@link #getDefaultSSLProtocol} method and the JVM-default provider.
   *
   * @return  The created SSL server socket factory.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL server socket
   *                                    factory.
   */
  @NotNull()
  public SSLServerSocketFactory createSSLServerSocketFactory()
         throws GeneralSecurityException
  {
    return new SetEnabledProtocolsAndCipherSuitesSSLServerSocketFactory(
         createSSLContext().getServerSocketFactory(),
         ENABLED_SSL_PROTOCOLS.get(), ENABLED_SSL_CIPHER_SUITES.get());
  }



  /**
   * Creates an SSL server socket factory using the configured key and trust
   * manager providers.  It will use the JVM-default provider.
   *
   * @param  protocol  The SSL protocol to use.  The Java Secure Socket
   *                   Extension (JSSE) Reference Guide provides a list of the
   *                   supported protocols, but commonly used values are
   *                   "TLSv1.3", "TLSv1.2", "TLSv1.1", and "TLSv1".  This must
   *                   not be {@code null}.
   *
   * @return  The created SSL server socket factory.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL server socket
   *                                    factory.
   */
  @NotNull()
  public SSLServerSocketFactory createSSLServerSocketFactory(
                                     @NotNull final String protocol)
         throws GeneralSecurityException
  {
    return new SetEnabledProtocolsAndCipherSuitesSSLServerSocketFactory(
         createSSLContext(protocol).getServerSocketFactory(), protocol,
         ENABLED_SSL_CIPHER_SUITES.get());
  }



  /**
   * Creates an SSL server socket factory using the configured key and trust
   * manager providers.
   *
   * @param  protocol  The SSL protocol to use.  The Java Secure Socket
   *                   Extension (JSSE) Reference Guide provides a list of the
   *                   supported protocols, but commonly used values are
   *                   "TLSv1.3", "TLSv1.2", "TLSv1.1", and "TLSv1".  This must
   *                   not be {@code null}.
   * @param  provider  The name of the provider to use for cryptographic
   *                   operations.  It must not be {@code null}.
   *
   * @return  The created SSL server socket factory.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL server socket
   *                                    factory.
   */
  @NotNull()
  public SSLServerSocketFactory createSSLServerSocketFactory(
                                     @NotNull final String protocol,
                                     @NotNull final String provider)
         throws GeneralSecurityException
  {
    return createSSLContext(protocol, provider).getServerSocketFactory();
  }



  /**
   * Retrieves the SSL protocol string that will be used by calls to
   * {@link #createSSLContext()} that do not explicitly specify which protocol
   * to use.
   *
   * @return  The SSL protocol string that will be used by calls to create an
   *          SSL context that do not explicitly specify which protocol to use.
   */
  @NotNull()
  public static String getDefaultSSLProtocol()
  {
    return DEFAULT_SSL_PROTOCOL.get();
  }



  /**
   * Specifies the SSL protocol string that will be used by calls to
   * {@link #createSSLContext()} that do not explicitly specify which protocol
   * to use.
   *
   * @param  defaultSSLProtocol  The SSL protocol string that will be used by
   *                             calls to create an SSL context that do not
   *                             explicitly specify which protocol to use.  It
   *                             must not be {@code null}.
   */
  public static void setDefaultSSLProtocol(
                          @NotNull final String defaultSSLProtocol)
  {
    Validator.ensureNotNull(defaultSSLProtocol);

    DEFAULT_SSL_PROTOCOL.set(defaultSSLProtocol);
  }



  /**
   * Retrieves the set of SSL protocols that will be enabled for use, if
   * available, for SSL sockets created within the LDAP SDK.
   *
   * @return  The set of SSL protocols that will be enabled for use, if
   *          available, for SSL sockets created within the LDAP SDK.
   */
  @NotNull()
  public static Set<String> getEnabledSSLProtocols()
  {
    return ENABLED_SSL_PROTOCOLS.get();
  }



  /**
   * Specifies the set of SSL protocols that will be enabled for use for SSL
   * sockets created within the LDAP SDK.  When creating an SSL socket, the
   * {@code SSLSocket.getSupportedProtocols} method will be used to determine
   * which protocols are supported for that socket, and then the
   * {@code SSLSocket.setEnabledProtocols} method will be used to enable those
   * protocols which are listed as both supported by the socket and included in
   * this set.  If the provided set is {@code null} or empty, then the default
   * set of enabled protocols will be used.
   *
   * @param  enabledSSLProtocols  The set of SSL protocols that will be enabled
   *                              for use for SSL sockets created within the
   *                              LDAP SDK.  It may be {@code null} or empty to
   *                              indicate that the JDK-default set of enabled
   *                              protocols should be used for the socket.
   */
  public static void setEnabledSSLProtocols(
              @Nullable final Collection<String> enabledSSLProtocols)
  {
    if (enabledSSLProtocols == null)
    {
      ENABLED_SSL_PROTOCOLS.set(Collections.<String>emptySet());
    }
    else
    {
      ENABLED_SSL_PROTOCOLS.set(Collections.unmodifiableSet(
           new LinkedHashSet<>(enabledSSLProtocols)));
    }
  }



  /**
   * Updates the provided socket to apply the appropriate set of enabled SSL
   * protocols.  This will only have any effect for sockets that are instances
   * of {@code javax.net.ssl.SSLSocket}, but it is safe to call for any kind of
   * {@code java.net.Socket}.  This should be called before attempting any
   * communication over the socket.
   *
   * @param  socket  The socket on which to apply the configured set of enabled
   *                 SSL protocols.
   *
   * @throws  LDAPException  If {@link #getEnabledSSLProtocols} returns a
   *                         non-empty set but none of the values in that set
   *                         are supported by the socket.
   */
  public static void applyEnabledSSLProtocols(@NotNull final Socket socket)
       throws LDAPException
  {
    try
    {
      applyEnabledSSLProtocols(socket, ENABLED_SSL_PROTOCOLS.get());
    }
    catch (final IOException ioe)
    {
      Debug.debugException(ioe);
      throw new LDAPException(ResultCode.CONNECT_ERROR, ioe.getMessage(), ioe);
    }
  }



  /**
   * Updates the provided socket to apply the appropriate set of enabled SSL
   * protocols.  This will only have any effect for sockets that are instances
   * of {@code javax.net.ssl.SSLSocket}, but it is safe to call for any kind of
   * {@code java.net.Socket}.  This should be called before attempting any
   * communication over the socket.
   *
   * @param  socket     The socket on which to apply the configured set of
   *                    enabled SSL protocols.
   * @param  protocols  The set of protocols that should be enabled for the
   *                    socket, if available.
   *
   * @throws  IOException  If a problem is encountered while applying the
   *                       desired set of enabled protocols to the given socket.
   */
  static void applyEnabledSSLProtocols(@Nullable final Socket socket,
                                       @NotNull final Set<String> protocols)
       throws IOException
  {
    if ((socket == null) || (!(socket instanceof SSLSocket)) ||
         protocols.isEmpty())
    {
      return;
    }

    final SSLSocket sslSocket = (SSLSocket) socket;
    final String[] protocolsToEnable =
         getSSLProtocolsToEnable(protocols, sslSocket.getSupportedProtocols());

    try
    {
      sslSocket.setEnabledProtocols(protocolsToEnable);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  /**
   * Updates the provided server socket to apply the appropriate set of enabled
   * SSL protocols.  This will only have any effect for server sockets that are
   * instances of {@code javax.net.ssl.SSLServerSocket}, but it is safe to call
   * for any kind of {@code java.net.ServerSocket}.  This should be called
   * before attempting any communication over the socket.
   *
   * @param  serverSocket  The server socket on which to apply the configured
   *                       set of enabled SSL protocols.
   * @param  protocols     The set of protocols that should be enabled for the
   *                       server socket, if available.
   *
   * @throws  IOException  If a problem is encountered while applying the
   *                       desired set of enabled protocols to the given server
   *                       socket.
   */
  static void applyEnabledSSLProtocols(
                   @Nullable final ServerSocket serverSocket,
                   @NotNull final Set<String> protocols)
       throws IOException
  {
    if ((serverSocket == null) ||
         (!(serverSocket instanceof SSLServerSocket)) ||
         protocols.isEmpty())
    {
      return;
    }

    final SSLServerSocket sslServerSocket = (SSLServerSocket) serverSocket;
    final String[] protocolsToEnable = getSSLProtocolsToEnable(protocols,
         sslServerSocket.getSupportedProtocols());

    try
    {
      sslServerSocket.setEnabledProtocols(protocolsToEnable);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  /**
   * Retrieves the names of the SSL protocols that should be enabled given the
   * provided information.
   *
   * @param  desiredProtocols    The set of protocols that are desired to be
   *                             enabled.
   * @param  supportedProtocols  The set of all protocols that are supported.
   *
   * @return  The names of the SSL protocols that should be enabled.
   *
   * @throws  IOException  If none of the desired values are included in the
   *                       supported set.
   */
  @NotNull()
  private static String[] getSSLProtocolsToEnable(
                               @NotNull final Set<String> desiredProtocols,
                               @NotNull final String[] supportedProtocols)
          throws IOException
  {
    final Set<String> lowerProtocols = new LinkedHashSet<>(
         StaticUtils.computeMapCapacity(desiredProtocols.size()));
    for (final String s : desiredProtocols)
    {
      lowerProtocols.add(StaticUtils.toLowerCase(s));
    }

    final ArrayList<String> enabledList =
         new ArrayList<>(supportedProtocols.length);
    for (final String supportedProtocol : supportedProtocols)
    {
      if (lowerProtocols.contains(StaticUtils.toLowerCase(supportedProtocol)))
      {
        enabledList.add(supportedProtocol);
      }
    }

    if (enabledList.isEmpty())
    {
      final StringBuilder enabledBuffer = new StringBuilder();
      final Iterator<String> enabledIterator = desiredProtocols.iterator();
      while (enabledIterator.hasNext())
      {
        enabledBuffer.append('\'');
        enabledBuffer.append(enabledIterator.next());
        enabledBuffer.append('\'');

        if (enabledIterator.hasNext())
        {
          enabledBuffer.append(", ");
        }
      }

      final StringBuilder supportedBuffer = new StringBuilder();
      for (int i=0; i < supportedProtocols.length; i++)
      {
        if (i > 0)
        {
          supportedBuffer.append(", ");
        }

        supportedBuffer.append('\'');
        supportedBuffer.append(supportedProtocols[i]);
        supportedBuffer.append('\'');
      }

      throw new IOException(
           ERR_NO_ENABLED_SSL_PROTOCOLS_AVAILABLE_FOR_SOCKET.get(
                enabledBuffer.toString(), supportedBuffer.toString(),
                PROPERTY_ENABLED_SSL_PROTOCOLS,
                SSLUtil.class.getName() + ".setEnabledSSLProtocols"));
    }
    else
    {
      return enabledList.toArray(StaticUtils.NO_STRINGS);
    }
  }



  /**
   * Retrieves the set of SSL cipher suites that will be enabled for use, if
   * available, for SSL sockets created within the LDAP SDK.
   *
   * @return  The set of SSL cipher suites that will be enabled for use, if
   *          available, for SSL sockets created within the LDAP SDK.
   */
  @NotNull()
  public static Set<String> getEnabledSSLCipherSuites()
  {
    return ENABLED_SSL_CIPHER_SUITES.get();
  }



  /**
   * Specifies the set of SSL cipher suites that will be enabled for SSL sockets
   * created within the LDAP SDK.  When creating an SSL socket, the
   * {@code SSLSocket.getSupportedCipherSuites} method will be used to determine
   * which cipher suites are supported for that socket, and then the
   * {@code SSLSocket.setEnabledCipherSuites} method will be used to enable
   * those suites which are listed as both supported by the socket and included
   * in this set.  If the provided set is {@code null} or empty, then the
   * default set of enabled cipher suites will be used.
   *
   * @param  enabledSSLCipherSuites  The set of SSL cipher suites that will be
   *                                 enabled for use for SSL sockets created
   *                                 within the LDAP SDK.  It may be
   *                                 {@code null} or empty to indicate that the
   *                                 JDK-default set of enabled cipher suites
   *                                 should be used for the socket.
   */
  public static void setEnabledSSLCipherSuites(
              @Nullable final Collection<String> enabledSSLCipherSuites)
  {
    if (enabledSSLCipherSuites == null)
    {
      ENABLED_SSL_CIPHER_SUITES.set(Collections.<String>emptySet());
    }
    else
    {
      ENABLED_SSL_CIPHER_SUITES.set(Collections.unmodifiableSet(
           new LinkedHashSet<>(enabledSSLCipherSuites)));
    }
  }



  /**
   * Updates the provided socket to apply the appropriate set of enabled SSL
   * cipher suites.  This will only have any effect for sockets that are
   * instances of {@code javax.net.ssl.SSLSocket}, but it is safe to call for
   * any kind of {@code java.net.Socket}.  This should be called before
   * attempting any communication over the socket.
   *
   * @param  socket  The socket on which to apply the configured set of enabled
   *                 SSL cipher suites.
   *
   * @throws  LDAPException  If {@link #getEnabledSSLCipherSuites} returns a
   *                         non-empty set but none of the values in that set
   *                         are supported by the socket.
   */
  public static void applyEnabledSSLCipherSuites(@NotNull final Socket socket)
         throws LDAPException
  {
    try
    {
      applyEnabledSSLCipherSuites(socket, ENABLED_SSL_CIPHER_SUITES.get());
    }
    catch (final IOException ioe)
    {
      Debug.debugException(ioe);
      throw new LDAPException(ResultCode.CONNECT_ERROR, ioe.getMessage(), ioe);
    }
  }



  /**
   * Updates the provided socket to apply the appropriate set of enabled SSL
   * cipher suites.  This will only have any effect for sockets that are
   * instances of {@code javax.net.ssl.SSLSocket}, but it is safe to call for
   * any kind of {@code java.net.Socket}.  This should be called before
   * attempting any communication over the socket.
   *
   * @param  socket        The socket on which to apply the configured set of
   *                       enabled SSL cipher suites.
   * @param  cipherSuites  The set of cipher suites that should be enabled for
   *                       the socket, if available.
   *
   * @throws  IOException  If a problem is encountered while applying the
   *                       desired set of enabled cipher suites to the given
   *                       socket.
   */
  static void applyEnabledSSLCipherSuites(@Nullable final Socket socket,
                   @NotNull final Set<String> cipherSuites)
         throws IOException
  {
    if ((socket == null) || (!(socket instanceof SSLSocket)) ||
        cipherSuites.isEmpty())
    {
      return;
    }

    final SSLSocket sslSocket = (SSLSocket) socket;
    final String[] cipherSuitesToEnable =
         getSSLCipherSuitesToEnable(cipherSuites,
              sslSocket.getSupportedCipherSuites());

    try
    {
      sslSocket.setEnabledCipherSuites(cipherSuitesToEnable);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  /**
   * Updates the provided server socket to apply the appropriate set of enabled
   * SSL cipher suites.  This will only have any effect for server sockets that
   * are instances of {@code javax.net.ssl.SSLServerSocket}, but it is safe to
   * call for any kind of {@code java.net.ServerSocket}.  This should be called
   * before attempting any communication over the socket.
   *
   * @param  serverSocket     The server socket on which to apply the configured
   *                          set of enabled SSL cipher suites.
   * @param  cipherSuites     The set of cipher suites that should be enabled
   *                          for the server socket, if available.
   *
   * @throws  IOException  If a problem is encountered while applying the
   *                       desired set of enabled cipher suites to the given
   *                       server socket.
   */
  static void applyEnabledSSLCipherSuites(
                   @Nullable final ServerSocket serverSocket,
                   @NotNull final Set<String> cipherSuites)
         throws IOException
  {
    if ((serverSocket == null) ||
        (! (serverSocket instanceof SSLServerSocket)) ||
        cipherSuites.isEmpty())
    {
      return;
    }

    final SSLServerSocket sslServerSocket = (SSLServerSocket) serverSocket;
    final String[] cipherSuitesToEnable =
         getSSLCipherSuitesToEnable(cipherSuites,
         sslServerSocket.getSupportedCipherSuites());

    try
    {
      sslServerSocket.setEnabledCipherSuites(cipherSuitesToEnable);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  /**
   * Retrieves the names of the SSL cipher suites that should be enabled given
   * the provided information.
   *
   * @param  desiredCipherSuites    The set of cipher suites that are desired to
   *                                be enabled.
   * @param  supportedCipherSuites  The set of all cipher suites that are
   *                                supported.
   *
   * @return  The names of the SSL cipher suites that should be enabled.
   *
   * @throws  IOException  If none of the desired values are included in the
   *                       supported set.
   */
  @NotNull()
  private static String[] getSSLCipherSuitesToEnable(
                               @NotNull final Set<String> desiredCipherSuites,
                               @NotNull final String[] supportedCipherSuites)
         throws IOException
  {
    final Set<String> upperCipherSuites = new LinkedHashSet<>(
         StaticUtils.computeMapCapacity(desiredCipherSuites.size()));
    for (final String s : desiredCipherSuites)
    {
      upperCipherSuites.add(StaticUtils.toUpperCase(s));
    }

    final ArrayList<String> enabledList =
         new ArrayList<>(supportedCipherSuites.length);
    for (final String supportedCipherSuite : supportedCipherSuites)
    {
      if (upperCipherSuites.contains(StaticUtils.toUpperCase(
           supportedCipherSuite)))
      {
        enabledList.add(supportedCipherSuite);
      }
    }

    if (enabledList.isEmpty())
    {
      final StringBuilder enabledBuffer = new StringBuilder();
      final Iterator<String> enabledIterator = desiredCipherSuites.iterator();
      while (enabledIterator.hasNext())
      {
        enabledBuffer.append('\'');
        enabledBuffer.append(enabledIterator.next());
        enabledBuffer.append('\'');

        if (enabledIterator.hasNext())
        {
          enabledBuffer.append(", ");
        }
      }

      final StringBuilder supportedBuffer = new StringBuilder();
      for (int i=0; i < supportedCipherSuites.length; i++)
      {
        if (i > 0)
        {
          supportedBuffer.append(", ");
        }

        supportedBuffer.append('\'');
        supportedBuffer.append(supportedCipherSuites[i]);
        supportedBuffer.append('\'');
      }

      throw new IOException(
           ERR_NO_ENABLED_SSL_CIPHER_SUITES_AVAILABLE_FOR_SOCKET.get(
                enabledBuffer.toString(), supportedBuffer.toString(),
                PROPERTY_ENABLED_SSL_CIPHER_SUITES,
                SSLUtil.class.getName() + ".setEnabledSSLCipherSuites"));
    }
    else
    {
      return enabledList.toArray(StaticUtils.NO_STRINGS);
    }
  }



  /**
   * Configures SSL default settings for the LDAP SDK.  This method is
   * non-private for purposes of easier test coverage.
   */
  static void configureSSLDefaults()
  {
    // Determine the set of TLS protocols that the JVM supports.
    String tls13Protocol = null;
    String tls12Protocol = null;
    String tls11Protocol = null;
    String tls1Protocol = null;
    try
    {
      final SSLContext defaultContext = CryptoHelper.getDefaultSSLContext();
      for (final String supportedProtocol :
           defaultContext.getSupportedSSLParameters().getProtocols())
      {
        if (supportedProtocol.equalsIgnoreCase(SSL_PROTOCOL_TLS_1_3))
        {
          tls13Protocol = supportedProtocol;
        }
        else if (supportedProtocol.equalsIgnoreCase(SSL_PROTOCOL_TLS_1_2))
        {
          tls12Protocol = supportedProtocol;
        }
        else if (supportedProtocol.equalsIgnoreCase(SSL_PROTOCOL_TLS_1_1))
        {
          tls11Protocol = supportedProtocol;
        }
        else if (supportedProtocol.equalsIgnoreCase(SSL_PROTOCOL_TLS_1))
        {
          tls1Protocol = supportedProtocol;
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    // Determine the set of TLS protocols that should be enabled.
    final String enabledProtocolsPropertyValue =
         StaticUtils.getSystemProperty(PROPERTY_ENABLED_SSL_PROTOCOLS);
    final Set<String> enabledProtocols = new LinkedHashSet<>();
    if (enabledProtocolsPropertyValue != null)
    {
      final StringTokenizer tokenizer =
           new StringTokenizer(enabledProtocolsPropertyValue, ", ", false);
      while (tokenizer.hasMoreTokens())
      {
        final String enabledProtocol = tokenizer.nextToken().trim();
        if (! enabledProtocol.isEmpty())
        {
          enabledProtocols.add(enabledProtocol);
        }
      }
    }
    else
    {
      if (tls13Protocol != null)
      {
        enabledProtocols.add(tls13Protocol);
        if (tls12Protocol != null)
        {
          enabledProtocols.add(tls12Protocol);
        }
      }
      else if (tls12Protocol != null)
      {
        enabledProtocols.add(tls12Protocol);
      }
      else if (tls11Protocol != null)
      {
        enabledProtocols.add(tls11Protocol);
      }
      else if (tls1Protocol != null)
      {
        enabledProtocols.add(tls1Protocol);
      }
    }

    ENABLED_SSL_PROTOCOLS.set(Collections.unmodifiableSet(enabledProtocols));


    // Determine the default TLS protocol.
    final String defaultProtocol;
    final String defaultProtocolPropertyValue =
         StaticUtils.getSystemProperty(PROPERTY_DEFAULT_SSL_PROTOCOL);
    if (defaultProtocolPropertyValue != null)
    {
      defaultProtocol = defaultProtocolPropertyValue;
    }
    else
    {
      defaultProtocol = enabledProtocols.iterator().next();
    }

    DEFAULT_SSL_PROTOCOL.set(defaultProtocol);


    // Determine the set of TLS cipher suites to enable by default.
    TLSCipherSuiteSelector.recompute();
    final String enabledSuitesPropertyValue =
         StaticUtils.getSystemProperty(PROPERTY_ENABLED_SSL_CIPHER_SUITES);
    final LinkedHashSet<String> enabledCipherSuites = new LinkedHashSet<>();
    if ((enabledSuitesPropertyValue != null) &&
         (! enabledSuitesPropertyValue.isEmpty()))
    {
      final StringTokenizer tokenizer =
           new StringTokenizer(enabledSuitesPropertyValue, ", ", false);
      while (tokenizer.hasMoreTokens())
      {
        final String token = tokenizer.nextToken().trim();
        if (! token.isEmpty())
        {
          enabledCipherSuites.add(token);
        }
      }
    }
    else
    {
      enabledCipherSuites.addAll(
           TLSCipherSuiteSelector.getDefaultCipherSuites());
    }

    ENABLED_SSL_CIPHER_SUITES.set(enabledCipherSuites);
  }



  /**
   * Creates a string representation of the provided certificate.
   *
   * @param  certificate  The certificate for which to generate the string
   *                      representation.  It must not be {@code null}.
   *
   * @return  A string representation of the provided certificate.
   */
  @NotNull()
  public static String certificateToString(
                            @NotNull final X509Certificate certificate)
  {
    final StringBuilder buffer = new StringBuilder();
    certificateToString(certificate, buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of the provided certificate to the given
   * buffer.
   *
   * @param  certificate  The certificate for which to generate the string
   *                      representation.  It must not be {@code null}.
   * @param  buffer       The buffer to which to append the string
   *                      representation.
   */
  public static void certificateToString(
                          @NotNull final X509Certificate certificate,
                          @NotNull final StringBuilder buffer)
  {
    buffer.append("Certificate(subject='");
    buffer.append(
         certificate.getSubjectX500Principal().getName(X500Principal.RFC2253));
    buffer.append("', serialNumber=");
    buffer.append(certificate.getSerialNumber());
    buffer.append(", notBefore=");
    StaticUtils.encodeGeneralizedTime(certificate.getNotBefore());
    buffer.append(", notAfter=");
    StaticUtils.encodeGeneralizedTime(certificate.getNotAfter());
    buffer.append(", signatureAlgorithm='");
    buffer.append(certificate.getSigAlgName());
    buffer.append("', signatureBytes='");
    StaticUtils.toHex(certificate.getSignature(), buffer);
    buffer.append("', issuerSubject='");
    buffer.append(
         certificate.getIssuerX500Principal().getName(X500Principal.RFC2253));
    buffer.append("')");
  }
}
