/*
 * Copyright 2008-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2022 Ping Identity Corporation
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
 * Copyright (C) 2008-2022 Ping Identity Corporation
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
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
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
import com.unboundid.util.ThreadLocalSecureRandom;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides a relatively simple interface for helping to configure
 * secure communication using TLS (formerly known as SSL) and StartTLS (which
 * uses an LDAP extended operation to convert an already-established non-secure
 * connection to one that uses TLS security).  When establishing secure
 * connections, there are five main concepts to be aware of:
 * <UL>
 *   <LI>The allowed set of TLS protocol versions</LI>
 *   <LI>The allowed set of TLS cipher suites</LI>
 *   <LI>The key manager (if any) to use for obtaining local certificates</LI>
 *   <LI>The trust manager to use for determining whether to trust peer
 *       certificates</LI>
 *   <LI>The logic used to validate certificate hostnames</LI>
 * </UL>
 * Each of these is covered in more detail below.
 * <BR><BR>
 * <H2>TLS Protocol Versions</H2>
 * The TLS protocol has evolved over time to improve both security and
 * efficiency, and each update to the protocol has been assigned a version
 * number.  At present, only TLSv1.3 and TLSv1.2 are considered secure, and only
 * those versions will be enabled by default, with TLSv1.3 preferred over
 * TLSv1.2.  Note that some older JVMs do not support TLSv1.3, and only TLSv1.2
 * will be enabled by default in that case.  In the very unlikely event that the
 * JVM does not support either TLSv1.3 or TLSv1.2, the LDAP SDK may fall back to
 * enabling support for TLSv1.1 or TLSv1.
 * <BR><BR>
 * If you want or need to explicitly specify the TLS protocol versions to use
 * for secure communication, then you may use the
 * {@link #setEnabledSSLProtocols} method to indicate which protocol versions
 * are allowed, and the {@link #setDefaultSSLProtocol} method to indicate which
 * is the preferred protocol version.  You can use any TLS protocol version that
 * the underlying JVM supports.
 * <BR><BR>
 * It is also possible to specify the set of enabled and default TLS protocol
 * versions using Java system properties.  The
 * {@code com.unboundid.util.SSLUtil.enabledSSLProtocols} property may be set
 * with a comma-delimited list of the TLS protocol versions that should be
 * enabled by default, and the
 * {@code com.unboundid.util.SSLUtil.defaultSSLProtocol} property  may be set
 * with the protocol version that should be preferred.  If set, these properties
 * will override the logic that the LDAP SDK automatically uses to select
 * default values, but those defaults may be explicitly overridden by calls to
 * the {@code setEnabledSSLProtocols} and {@code setDefaultSSLProtocol} methods.
 * <BR><BR>
 * <H2>TLS Cipher Suites</H2>
 * A cipher suite encapsulates a number of settings that will be used to
 * actually secure TLS communication between two systems, including which
 * algorithm to use for key exchange, which algorithm to use for bulk
 * encryption, and which algorithm to use for integrity protection.  The JVM
 * supports a fixed set of TLS cipher suites, although it may only enable
 * support for a subset of those by default, and the LDAP SDK may further
 * disable support for some of those suites by default for security reasons.
 * The logic that the LDAP SDK uses to select a good default set of TLS cipher
 * suites is encapsulated in the {@link TLSCipherSuiteSelector} class, and the
 * class-level documentation for that class describes the criteria that it uses
 * to make its selection.
 * <BR><BR>
 * If you wish to override the LDAP SDK's default selection, you may use the
 * {@link #setEnabledSSLCipherSuites} method to explicitly specify the set of
 * cipher suites that should be enabled.  Alternatively, the
 * {@code com.unboundid.util.SSLUtil.enabledSSLCipherSuites} system property may
 * be set with a comma-delimited list of the cipher suites that should be
 * enabled.
 * <BR><BR>
 * <H2>Key Managers</H2>
 * A key manager is used to obtain access to a certificate chain and private key
 * that should be presented to the peer during TLS negotiation.  In the most
 * common use cases, in which the LDAP SDK is used only to establish outbound
 * connections and does not need to use a certificate to authenticate itself to
 * the LDAP server, there won't be any need to present a certificate chain, and
 * there won't be any need to configure a key manager.  However, if you are
 * using the LDAP SDK to accept TLS-secured connections from LDAP clients (for
 * example, using the
 * {@link com.unboundid.ldap.listener.InMemoryDirectoryServer} or
 * another type of {@link com.unboundid.ldap.listener.LDAPListener}), if the
 * server requires clients to present their own certificate for mutual TLS
 * authentication, or if you want to use the SASL EXTERNAL mechanism to use a
 * client certificate to authenticate to the server at the LDAP layer, then you
 * will need to specify a key manager to provide access to that certificate
 * chain.  The key manager to use for that purpose should be provided in the
 * {@code SSLUtil} constructor.
 * <BR><BR>
 * While any {@code javax.net.ssl.KeyManager} instance can be used, the LDAP SDK
 * provides three options that will be sufficient for most use cases:
 * <UL>
 *   <LI>{@link KeyStoreKeyManager} -- Allows the certificate chain and private
 *       key to be obtained from a key store file, which will typically be in
 *       the JKS or PKCS #12 format (or in the Bouncy Castle BCFKS format when
 *       using the LDAP SDK in FIPS 140-2-compliant mode).</LI>
 *   <LI>{@link PEMFileKeyManager} -- Allows the certificate chain and private
 *       key to be obtained from text files that contain the PEM-encoded
 *       representation of X.509 certificates and a PKCS #8 private key.</LI>
 *   <LI>{@link PKCS11KeyManager} -- Allows the certificate chain and private
 *       key to be accessed from a PKCS #11 token, like a hardware security
 *       module (HSM).</LI>
 * </UL>
 * <BR><BR>
 * <H2>Trust Managers</H2>
 * A trust manager is used to determine whether to trust a certificate chain
 * presented by a peer during TLS negotiation.  Trust is a very important aspect
 * of TLS because it's important to make sure that the peer you're communicating
 * with is actually who you intend it to be and not someone else who has managed
 * to hijack the negotiation process.
 * <BR><BR>
 * You will generally always want to provide a trust manager, regardless of
 * whether you're using the LDAP SDK to act as a client or a server, and this
 * trust manager should be provided in the {@code SSLUtil} constructor.  The
 * LDAP SDK offers several trust manager implementations, including:
 * <UL>
 *   <LI>{@link JVMDefaultTrustManager} -- Uses the JVM's default
 *       {@code cacerts} trust store to obtain access to a set of trusted,
 *       well-known issuer certificates, including those from commercial
 *       certification authorities like Verisign or DigiCert, and from trusted
 *       free providers like Let's Encrypt.  This trust manager will only accept
 *       valid certificates that have been signed by one of those trusted
 *       authorities.</LI>
 *   <LI>{@link TrustStoreTrustManager} -- Uses the information in a trust store
 *       file (typically in a format like JKS, PKCS #12 or BCFKS) as a set of
 *       trusted certificates and issuers.</LI>
 *   <LI>{@link PEMFileTrustManager} -- Uses the information one or more files
 *       containing the PEM representations of X.509 certificates as a set of
 *       trusted certificates and issuers.</LI>
 *   <LI>{@link com.unboundid.ldap.sdk.unboundidds.TopologyRegistryTrustManager}
 *       -- Uses the topology registry information in the configuration of a
 *       Ping Identity Directory Server (or related server product) to obtain a
 *       set of trusted certificates and issuers.</LI>
 *   <LI>{@link PromptTrustManager} -- Interactively prompts the user (via the
 *       terminal) to determine whether the presented certificate chain should
 *       be trusted.</LI>
 *   <LI>{@link TrustAllTrustManager} -- Blindly trusts all certificate chains
 *       that are presented to it.  This may be convenient in some cases for
 *       testing purposes, but it is strongly discouraged for production use
 *       because it does not actually perform any real trust processing and will
 *       allow connecting to unintended or malicious peers.</LI>
 *   <LI>{@link AggregateTrustManager} -- Allows you to combine multiple other
 *       trust managers in the course of determining whether to trust a
 *       presented certificate chain.  For example, you may use this to
 *       automatically trust certificates signed by an issuer in the JVM's
 *       {@code cacerts} file or in an explicitly specified alternative trust
 *       store file, but to fall back to interactively prompting the user for
 *       certificates not trusted by one of the previous two methods.</LI>
 * </UL>
 * <BR><BR>
 * <H2>Certificate Hostname Validation</H2>
 * Trust managers can be used to ensure that a certificate chain presented by a
 * peer originally came from a trusted source, but that doesn't necessarily mean
 * that the peer system is the one you intend it to be.  It's not at all
 * difficult for malicious users and applications to obtain a certificate that
 * is signed by a CA in the JVM's default set of trusted issuers.  However, any
 * certificate signed by one of those trusted issuers will include information
 * in a subject alternative name extension that specifies the hostnames (or at
 * least domain names) and IP addresses for systems with which that certificate
 * is allowed to be used, and those issues are careful to verify that they only
 * issue certificates to systems that are legitimately associated with those
 * systems.  So while a malicious user may be able to easily get a certificate
 * from a trusted issuer, it should not be possible for them to get a
 * certificate with a subject alternative name extension containing addresses
 * they don't legitimately have the right to use.
 * <BR><BR>
 * Because of this, it's very important that clients not only verify that the
 * server's certificate comes from a trusted source, but also that it's allowed
 * to be used by that server system.  This additional level of validation can
 * help thwart attacks that rely on DNS hijacking or other methods of diverting
 * communication away from the intended recipient to one that an attacker
 * controls instead.  The LDAP SDK does not perform this validation by default
 * because there are unfortunately too many cases in which clients (especially
 * those used in testing and development environments) might need to interact
 * with a server whose certificate may not have an appropriate subject
 * alternative name extension.  However, in production environments with a
 * properly configured TLS certificate, hostname verification can be enabled by
 * calling the
 * {@link com.unboundid.ldap.sdk.LDAPConnectionOptions#setSSLSocketVerifier}
 * method with an instance of the {@link HostNameSSLSocketVerifier}.
 * Alternatively, you can set the {@code com.unboundid.ldap.sdk.
 * LDAPConnectionOptions.defaultVerifyCertificateHostnames} system property with
 * a value of "{@code true}" to enable this validation by default.
 * <BR><BR>
 * <H2>Examples</H2>
 * The following example demonstrates the process for establish a secure client
 * connection.  It relies on the LDAP SDK's default configuration for selecting
 * TLS protocols and cipher suites, and does not use a key manager.  It uses an
 * aggregate trust manager to automatically trust any certificates signed by one
 * of the JVM's default trusted issuers or an issuer in an explicitly specified
 * key store file, and it enables host name validation.
 * <BR><BR>
 * <PRE>
 *   AggregateTrustManager trustManager = new AggregateTrustManager(false,
 *        JVMDefaultTrustManager.getInstance(),
 *        new TrustStoreTrustManager(trustStorePath, trustStorePIN,
 *             "PKCS12", true));
 *   SSLUtil sslUtil = new SSLUtil(trustManager);
 *
 *   LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
 *   connectionOptions.setSSLSocketVerifier(
 *        new HostNameSSLSocketVerifier(true));
 *
 *   try (LDAPConnection connection = new LDAPConnection(
 *             sslUtil.createSSLSocketFactory(), connectionOptions,
 *             serverAddress, serverLDAPSPort))
 *   {
 *     // Use the connection here.
 *     RootDSE rootDSE = connection.getRootDSE();
 *   }
 * </PRE>
 * <BR><BR>
 * The above example establishes an LDAPS connection that is secured by TLS as
 * soon as it is created.  The following example shows the process needed to use
 * the StartTLS extended operation to secure an already-established non-secure
 * connection:
 * <BR><BR>
 * <PRE>
 *   AggregateTrustManager trustManager = new AggregateTrustManager(false,
 *        JVMDefaultTrustManager.getInstance(),
 *        new TrustStoreTrustManager(trustStorePath, trustStorePIN,
 *             "PKCS12", true));
 *   SSLUtil sslUtil = new SSLUtil(trustManager);
 *
 *   LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
 *   connectionOptions.setSSLSocketVerifier(
 *        new HostNameSSLSocketVerifier(true));
 *
 *   try (LDAPConnection connection = new LDAPConnection(
 *             connectionOptions, serverAddress, serverLDAPPort))
 *   {
 *     // Use the StartTLS extended operation to secure the connection.
 *     ExtendedResult startTLSResult;
 *     try
 *     {
 *       startTLSResult = connection.processExtendedOperation(
 *            new StartTLSExtendedRequest(
 *                 sslUtil.createSSLSocketFactory()));
 *     }
 *     catch (LDAPException e)
 *     {
 *       Debug.debugException(e);
 *       startTLSResult = new ExtendedResult(e);
 *     }
 *     LDAPTestUtils.assertResultCodeEquals(startTLSResult,
 *          ResultCode.SUCCESS);
 *
 *     // Use the connection here.
 *     RootDSE rootDSE = connection.getRootDSE();
 *   }
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
                 TLSCipherSuiteSelector.getRecommendedCipherSuites()));



  /**
   * The default set of SSL protocols that will be enabled for use if available
   * for SSL sockets created within the LDAP SDK.
   */
  @NotNull private static final AtomicReference<Set<String>>
       ENABLED_SSL_PROTOCOLS = new AtomicReference<>(
            StaticUtils.setOf(SSL_PROTOCOL_TLS_1_2));



  /**
   * The name of the service type that providers use to indicate the
   * {@code SSLContext} algorithms that they support.
   */
  @NotNull static final String PROVIDER_SERVICE_TYPE_SSL_CONTEXT =
       "SSLContext";



  /**
   * Indicates whether SSL/TLS debugging is expected to be enabled, based on
   * the javax.net.debug system property.
   */
  private static final boolean JVM_SSL_DEBUGGING_ENABLED =
       TLSCipherSuiteSelector.jvmSSLDebuggingEnabled();



  static
  {
    configureSSLDefaults();
  }



  // Indicates whether any of the provided key managers is a PKCS #11 key
  // manager.
  private final boolean usingPKCS11KeyManager;

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
    usingPKCS11KeyManager = false;
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
    usingPKCS11KeyManager = false;

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
    usingPKCS11KeyManager = false;

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
      usingPKCS11KeyManager = false;
    }
    else
    {
      keyManagers = new KeyManager[] { keyManager };
      usingPKCS11KeyManager = (keyManager instanceof PKCS11KeyManager);
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
      usingPKCS11KeyManager = false;
    }
    else
    {
      this.keyManagers = keyManagers;

      boolean usingPKCS11 = false;
      for (final KeyManager km : keyManagers)
      {
        if (km instanceof PKCS11KeyManager)
        {
          usingPKCS11 = true;
          break;
        }
      }

      usingPKCS11KeyManager = usingPKCS11;
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

    SSLContext sslContext = null;
    if (usingPKCS11KeyManager)
    {
      final Provider pkcs11JSSEProvider =
           PKCS11KeyManager.getPKCS11JSSESProvider();
      if ((pkcs11JSSEProvider != null) && (pkcs11JSSEProvider.getService(
           PROVIDER_SERVICE_TYPE_SSL_CONTEXT, protocol) != null))
      {
        if (JVM_SSL_DEBUGGING_ENABLED)
        {
          System.err.println("SSLUtil.createSSLContext creating a PKCS #11 " +
               "SSLContext for protocol " + protocol);
        }

        sslContext = CryptoHelper.getSSLContext(protocol, pkcs11JSSEProvider);
      }
    }

    if (sslContext == null)
    {
      if (JVM_SSL_DEBUGGING_ENABLED)
      {
        System.err.println("SSLUtil.createSSLContext creating an SSLContext " +
             "for protocol " + protocol);
      }

      sslContext = CryptoHelper.getSSLContext(protocol);
    }

    sslContext.init(keyManagers, trustManagers, ThreadLocalSecureRandom.get());
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

    if (JVM_SSL_DEBUGGING_ENABLED)
    {
      System.err.println("SSLUtil.createSSLContext creating an SSLContext " +
           "for protocol " + protocol + " and provider " + provider);
    }

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
    if (JVM_SSL_DEBUGGING_ENABLED)
    {
      System.err.println("SSLUtil.createSSLSocketFactory creating a " +
           "SetEnabledProtocolsAndCipherSuitesSSLSocketFactory with enabled " +
           "protocols " + ENABLED_SSL_PROTOCOLS.get() +
           " and enabled cipher suites " + ENABLED_SSL_CIPHER_SUITES.get());
    }

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
    if (JVM_SSL_DEBUGGING_ENABLED)
    {
      System.err.println("SSLUtil.createSSLSocketFactory creating a " +
           "SetEnabledProtocolsAndCipherSuitesSSLSocketFactory with protocol " +
           protocol + " and enabled cipher suites " +
           ENABLED_SSL_CIPHER_SUITES.get());
    }

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
    if (JVM_SSL_DEBUGGING_ENABLED)
    {
      System.err.println("SSLUtil.createSSLSocketFactory creating an " +

           "SetEnabledProtocolsAndCipherSuitesSSLSocketFactory with protocol " +
           protocol + ", provider " + provider +
           ", and enabled cipher suites " + ENABLED_SSL_CIPHER_SUITES.get());
    }

    return new SetEnabledProtocolsAndCipherSuitesSSLSocketFactory(
         createSSLContext(protocol, provider).getSocketFactory(), protocol,
         ENABLED_SSL_CIPHER_SUITES.get());
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
    if (JVM_SSL_DEBUGGING_ENABLED)
    {
      System.err.println("SSLUtil.createSSLServerSocketFactory creating a " +
           "SetEnabledProtocolsAndCipherSuitesSSLServerSocketFactory with " +
           "enabled protocols " + ENABLED_SSL_PROTOCOLS.get() +
           " and enabled cipher suites " + ENABLED_SSL_CIPHER_SUITES.get());
    }

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
    if (JVM_SSL_DEBUGGING_ENABLED)
    {
      System.err.println("SSLUtil.createSSLServerSocketFactory creating a " +
           "SetEnabledProtocolsAndCipherSuitesSSLServerSocketFactory with " +
           "protocol " + protocol + " and enabled cipher suites " +
           ENABLED_SSL_CIPHER_SUITES.get());
    }

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
    if (JVM_SSL_DEBUGGING_ENABLED)
    {
      System.err.println("SSLUtil.createSSLServerSocketFactory creating a " +
           "SetEnabledProtocolsAndCipherSuitesSSLServerSocketFactory with " +
           "protocol " + protocol + ", provider " + provider +
           ", and enabled cipher suites " + ENABLED_SSL_CIPHER_SUITES.get());
    }

    return new SetEnabledProtocolsAndCipherSuitesSSLServerSocketFactory(
         createSSLContext(protocol, provider).getServerSocketFactory(),
         protocol, ENABLED_SSL_CIPHER_SUITES.get());
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

    if (JVM_SSL_DEBUGGING_ENABLED)
    {
      System.err.println("SSLUtil.setDefaultSSLProtocol setting the " +
           "default SSL protocol to " + defaultSSLProtocol);
    }

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
      if (JVM_SSL_DEBUGGING_ENABLED)
      {
        System.err.println("SSLUtil.setEnabledSSLProtocols setting the " +
             "enabled SSL protocols to an empty set");
      }

      ENABLED_SSL_PROTOCOLS.set(Collections.<String>emptySet());
    }
    else
    {
      if (JVM_SSL_DEBUGGING_ENABLED)
      {
        System.err.println("SSLUtil.setEnabledSSLProtocols setting the " +
             "enabled SSL protocols to " + enabledSSLProtocols);
      }

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
      if (JVM_SSL_DEBUGGING_ENABLED)
      {
        System.err.println("SSLUtil.applyEnabledSSLProtocols applying " +
             "protocolsToEnable " + Arrays.toString(protocolsToEnable) +
             " to SSLSocket " + sslSocket);
      }

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
      if (JVM_SSL_DEBUGGING_ENABLED)
      {
        System.err.println("SSLUtil.applyEnabledSSLProtocols applying " +
             "protocolsToEnable " + Arrays.toString(protocolsToEnable) +
             " to SSLServerSocket " + sslServerSocket);
      }

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
      if (JVM_SSL_DEBUGGING_ENABLED)
      {
        System.err.println("SSLUtil.setEnabledSSLCipherSuites setting the " +
             "enabled SSL cipher suites to an empty set");
      }

      ENABLED_SSL_CIPHER_SUITES.set(Collections.<String>emptySet());
    }
    else
    {
      if (JVM_SSL_DEBUGGING_ENABLED)
      {
        System.err.println("SSLUtil.setEnabledSSLCipherSuites setting the " +
             "enabled SSL cipher suites to " + enabledSSLCipherSuites);
      }

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
      if (JVM_SSL_DEBUGGING_ENABLED)
      {
        System.err.println("SSLUtil.applyEnabledSSLCipherSuites applying " +
             "cinpherSuitesToEnable " + Arrays.toString(cipherSuitesToEnable) +
             " to SSLSocket " + sslSocket);
      }

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
      if (JVM_SSL_DEBUGGING_ENABLED)
      {
        System.err.println("SSLUtil.applyEnabledSSLCipherSuites applying " +
             "cinpherSuitesToEnable " + Arrays.toString(cipherSuitesToEnable) +
             " to SSLServerSocket " + sslServerSocket);
      }

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
           TLSCipherSuiteSelector.getRecommendedCipherSuites());
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
