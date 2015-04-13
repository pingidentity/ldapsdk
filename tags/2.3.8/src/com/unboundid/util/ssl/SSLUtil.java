/*
 * Copyright 2008-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2014 UnboundID Corp.
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



import java.lang.reflect.Method;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Validator.*;
import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides a simple interface for creating {@code SSLContext} and
 * {@code SSLSocketFactory} instances, which may be used to create SSL-based
 * connections, or secure existing connections with StartTLS.
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
   * The name of the system property that can be used to specify the initial
   * value for the default SSL protocol that should be used.  If this is not
   * set, then the default SSL protocol will be dynamically determined.  This
   * can be overridden via the {@link #setDefaultSSLProtocol(String)} method.
   */
  public static final String PROPERTY_DEFAULT_SSL_PROTOCOL =
       "com.unboundid.util.SSLUtil.defaultSSLProtocol";



  /**
   * The name of the system property that can be used to provide the initial
   * set of enabled SSL protocols that should be used, as a comma-delimited
   * list.  If this is not set, then the enabled SSL protocols will be
   * dynamically determined.  This can be overridden via the
   * {@link #setEnabledSSLProtocols(java.util.Collection)} method.
   */
  public static final String PROPERTY_ENABLED_SSL_PROTOCOLS =
       "com.unboundid.util.SSLUtil.enabledSSLProtocols";



  /**
   * The default protocol string that will be used to create SSL contexts when
   * no explicit protocol is specified.
   */
  private static final AtomicReference<String> DEFAULT_SSL_PROTOCOL =
       new AtomicReference<String>("TLSv1");



  /**
   * The set of SSL protocols that will be enabled for use if available in SSL
   * SSL sockets created within the LDAP SDK.
   */
  private static final AtomicReference<Set<String>> ENABLED_SSL_PROTOCOLS =
       new AtomicReference<Set<String>>();



  /**
   * The set of SSL protocols, in all lowercase, that will be enabled for use if
   * available in SSL sockets created within the LDAP SDK.
   */
  private static final AtomicReference<Set<String>>
       LOWER_ENABLED_SSL_PROTOCOLS = new AtomicReference<Set<String>>();

  static
  {
    configureSSLDefaults();
  }



  // The set of key managers to be used.
  private final KeyManager[] keyManagers;

  // The set of trust managers to be used.
  private final TrustManager[] trustManagers;



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
  public SSLUtil(final TrustManager trustManager)
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
  public SSLUtil(final TrustManager[] trustManagers)
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
  public SSLUtil(final KeyManager keyManager, final TrustManager trustManager)
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
  public SSLUtil(final KeyManager[] keyManagers,
                 final TrustManager[] trustManagers)
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
  public SSLContext createSSLContext()
         throws GeneralSecurityException
  {
    return createSSLContext(DEFAULT_SSL_PROTOCOL.get());
  }



  /**
   * Creates an initialized SSL context created with the configured key and
   * trust managers.  It will use the default provider.
   *
   * @param  protocol  The protocol to use.  As per the Java SE 6 Cryptography
   *                   Architecture document, the set of supported protocols
   *                   should include at least "SSLv3", "TLSv1", "TLSv1.1", and
   *                   "SSLv2Hello".  It must not be {@code null}.
   *
   * @return  The created SSL context.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL context.
   */
  public SSLContext createSSLContext(final String protocol)
         throws GeneralSecurityException
  {
    ensureNotNull(protocol);

    final SSLContext sslContext = SSLContext.getInstance(protocol);
    sslContext.init(keyManagers, trustManagers, null);
    return sslContext;
  }



  /**
   * Creates an initialized SSL context created with the configured key and
   * trust managers.
   *
   * @param  protocol  The protocol to use.  As per the Java SE 6 Cryptography
   *                   Architecture document, the set of supported protocols
   *                   should include at least "SSLv3", "TLSv1", "TLSv1.1", and
   *                   "SSLv2Hello".  It must not be {@code null}.
   * @param  provider  The name of the provider to use for cryptographic
   *                   operations.  It must not be {@code null}.
   *
   * @return  The created SSL context.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL context.
   */
  public SSLContext createSSLContext(final String protocol,
                                     final String provider)
         throws GeneralSecurityException
  {
    ensureNotNull(protocol, provider);

    final SSLContext sslContext = SSLContext.getInstance(protocol, provider);
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
  public SSLSocketFactory createSSLSocketFactory()
         throws GeneralSecurityException
  {
    return createSSLContext().getSocketFactory();
  }



  /**
   * Creates an SSL socket factory with the configured key and trust managers.
   * It will use the default provider.
   *
   * @param  protocol  The protocol to use.  As per the Java SE 6 Cryptography
   *                   Architecture document, the set of supported protocols
   *                   should include at least "SSLv3", "TLSv1", "TLSv1.1", and
   *                   "SSLv2Hello".  It must not be {@code null}.
   *
   * @return  The created SSL socket factory.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL socket factory.
   */
  public SSLSocketFactory createSSLSocketFactory(final String protocol)
         throws GeneralSecurityException
  {
    return createSSLContext(protocol).getSocketFactory();
  }



  /**
   * Creates an SSL socket factory with the configured key and trust managers.
   *
   * @param  protocol  The protocol to use.  As per the Java SE 6 Cryptography
   *                   Architecture document, the set of supported protocols
   *                   should include at least "SSLv3", "TLSv1", "TLSv1.1", and
   *                   "SSLv2Hello".  It must not be {@code null}.
   * @param  provider  The name of the provider to use for cryptographic
   *                   operations.  It must not be {@code null}.
   *
   * @return  The created SSL socket factory.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL socket factory.
   */
  public SSLSocketFactory createSSLSocketFactory(final String protocol,
                                                 final String provider)
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
  public SSLServerSocketFactory createSSLServerSocketFactory()
         throws GeneralSecurityException
  {
    return createSSLContext().getServerSocketFactory();
  }



  /**
   * Creates an SSL server socket factory using the configured key and trust
   * manager providers.  It will use the JVM-default provider.
   *
   * @param  protocol  The protocol to use.  As per the Java SE 6 Cryptography
   *                   Architecture document, the set of supported protocols
   *                   should include at least "SSLv3", "TLSv1", "TLSv1.1", and
   *                   "SSLv2Hello".  It must not be {@code null}.
   *
   * @return  The created SSL server socket factory.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL server socket
   *                                    factory.
   */
  public SSLServerSocketFactory createSSLServerSocketFactory(
                                     final String protocol)
         throws GeneralSecurityException
  {
    return createSSLContext(protocol).getServerSocketFactory();
  }



  /**
   * Creates an SSL server socket factory using the configured key and trust
   * manager providers.
   *
   * @param  protocol  The protocol to use.  As per the Java SE 6 Cryptography
   *                   Architecture document, the set of supported protocols
   *                   should include at least "SSLv3", "TLSv1", "TLSv1.1", and
   *                   "SSLv2Hello".  It must not be {@code null}.
   * @param  provider  The name of the provider to use for cryptographic
   *                   operations.  It must not be {@code null}.
   *
   * @return  The created SSL server socket factory.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL server socket
   *                                    factory.
   */
  public SSLServerSocketFactory createSSLServerSocketFactory(
                                     final String protocol,
                                     final String provider)
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
  public static void setDefaultSSLProtocol(final String defaultSSLProtocol)
  {
    ensureNotNull(defaultSSLProtocol);

    DEFAULT_SSL_PROTOCOL.set(defaultSSLProtocol);
  }



  /**
   * Retrieves the set of SSL protocols that will be enabled for use, if
   * available, for SSL sockets created within the LDAP SDK.
   *
   * @return  The set of SSL protocols that will be enabled for use, if
   *          available, for SSL sockets created within the LDAP SDK.
   */
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
                          final Collection<String> enabledSSLProtocols)
  {
    if (enabledSSLProtocols == null)
    {
      ENABLED_SSL_PROTOCOLS.set(Collections.<String>emptySet());
      LOWER_ENABLED_SSL_PROTOCOLS.set(Collections.<String>emptySet());
    }
    else
    {
      final HashSet<String> lowerProtocols =
           new HashSet<String>(enabledSSLProtocols.size());
      for (final String s : enabledSSLProtocols)
      {
        lowerProtocols.add(StaticUtils.toLowerCase(s));
      }

      ENABLED_SSL_PROTOCOLS.set(Collections.unmodifiableSet(
           new HashSet<String>(enabledSSLProtocols)));
      LOWER_ENABLED_SSL_PROTOCOLS.set(Collections.unmodifiableSet(
           new HashSet<String>(lowerProtocols)));
    }
  }



  /**
   * Updates the provided socket to apply the appropriate set of enabled SSL
   * protocols.  This will only have any effect for sockets that are instances
   * of {@code javax.net.ssl.SSLSocket}, but it is safe to call for any kind of
   * {@code java.net.Socket}.  This should be called before attempting any
   * communication over the socket, as
   *
   * @param  socket  The socket on which to apply the configured set of enabled
   *                 SSL protocols.
   *
   * @throws  LDAPException  If {@link #getEnabledSSLProtocols} returns a
   *                         non-empty set but none of the values in that set
   *                         are supported by
   */
  public static void applyEnabledSSLProtocols(final Socket socket)
         throws LDAPException
  {
    if ((socket == null) || (!(socket instanceof SSLSocket)))
    {
      return;
    }

    final Set<String> lowerEnabledProtocols = LOWER_ENABLED_SSL_PROTOCOLS.get();
    if (lowerEnabledProtocols.isEmpty())
    {
      return;
    }

    final SSLSocket sslSocket = (SSLSocket) socket;
    final String[] supportedProtocols = sslSocket.getSupportedProtocols();

    final ArrayList<String> enabledList =
         new ArrayList<String>(supportedProtocols.length);
    for (final String supportedProtocol : supportedProtocols)
    {
      if (lowerEnabledProtocols.contains(
           StaticUtils.toLowerCase(supportedProtocol)))
      {
        enabledList.add(supportedProtocol);
      }
    }

    if (enabledList.isEmpty())
    {
      final StringBuilder enabledBuffer = new StringBuilder();
      final Iterator<String> enabledIterator =
           ENABLED_SSL_PROTOCOLS.get().iterator();
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

      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_NO_ENABLED_SSL_PROTOCOLS_AVAILABLE_FOR_SOCKET.get(
                enabledBuffer.toString(), supportedBuffer.toString(),
                PROPERTY_ENABLED_SSL_PROTOCOLS,
                SSLUtil.class.getName() + ".setEnabledSSLProtocols"));
    }
    else
    {
      final String[] enabledArray = new String[enabledList.size()];
      sslSocket.setEnabledProtocols(enabledList.toArray(enabledArray));
    }
  }



  /**
   * Configures SSL default settings for the LDAP SDK.  This method is
   * non-private for purposes of easier test coverage.
   */
  static void configureSSLDefaults()
  {
    // See if there is a system property that specifies what the default SSL
    // protocol should be.  If not, then try to dynamically determine it.
    final String defaultPropValue =
         System.getProperty(PROPERTY_DEFAULT_SSL_PROTOCOL);
    if ((defaultPropValue != null) && (defaultPropValue.length() > 0))
    {
      DEFAULT_SSL_PROTOCOL.set(defaultPropValue);
    }
    else
    {
      // Ideally, we should be able to discover the SSL protocol that offers the
      // best mix of security and compatibility.  Unfortunately, Java SE 5
      // doesn't expose the methods necessary to allow us to do that, but if the
      // running JVM is Java SE 6 or later, then we can use reflection to invoke
      // those methods and make the appropriate determination.  If we see that
      // TLSv1.1 and/or TLSv1.2 are available, then we'll add those to the set
      // of default enabled protocols.
      try
      {
        final Method getDefaultMethod =
             SSLContext.class.getMethod("getDefault");
        final SSLContext defaultContext =
             (SSLContext) getDefaultMethod.invoke(null);

        final Method getSupportedParamsMethod =
             SSLContext.class.getMethod("getSupportedSSLParameters");
        final Object paramsObj =
             getSupportedParamsMethod.invoke(defaultContext);

        final Class<?> sslParamsClass =
             Class.forName("javax.net.ssl.SSLParameters");
        final Method getProtocolsMethod =
             sslParamsClass.getMethod("getProtocols");
        final String[] supportedProtocols =
             (String[]) getProtocolsMethod.invoke(paramsObj);

        final HashSet<String> protocolMap =
             new HashSet<String>(Arrays.asList(supportedProtocols));
        if (protocolMap.contains("TLSv1.2"))
        {
          DEFAULT_SSL_PROTOCOL.set("TLSv1.2");
        }
        else if (protocolMap.contains("TLSv1.1"))
        {
          DEFAULT_SSL_PROTOCOL.set("TLSv1.1");
        }
        else if (protocolMap.contains("TLSv1"))
        {
          DEFAULT_SSL_PROTOCOL.set("TLSv1");
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    // A set to use for the default set of enabled protocols.  Unless otherwise
    // specified via system property, we'll always enable TLSv1.  We may enable
    // other protocols based on the default protocol.  The default set of
    // enabled protocols will not include SSLv3 even if the JVM might otherwise
    // include it as a default enabled protocol because of known security
    // problems with SSLv3.
    final HashSet<String> enabledProtocols = new HashSet<String>(10);
    enabledProtocols.add("TLSv1");
    if (DEFAULT_SSL_PROTOCOL.get().equals("TLSv1.2"))
    {
      enabledProtocols.add("TLSv1.1");
      enabledProtocols.add("TLSv1.2");
    }
    else if (DEFAULT_SSL_PROTOCOL.get().equals("TLSv1.1"))
    {
      enabledProtocols.add("TLSv1.1");
    }

    // If there is a system property that specifies which enabled SSL protocols
    // to use, then it will override the defaults.
    final String enabledPropValue =
         System.getProperty(PROPERTY_ENABLED_SSL_PROTOCOLS);
    if ((enabledPropValue != null) && (enabledPropValue.length() > 0))
    {
      enabledProtocols.clear();

      final StringTokenizer tokenizer = new StringTokenizer(enabledPropValue,
           ", ", false);
      while (tokenizer.hasMoreTokens())
      {
        final String token = tokenizer.nextToken();
        if (token.length() > 0)
        {
          enabledProtocols.add(token);
        }
      }
    }

    // Get all-lowercase representations of the enabled protocols for more
    // efficient comparisons.
    final HashSet<String> lowerEnabledProtocols =
         new HashSet<String>(enabledProtocols.size());
    for (final String s : enabledProtocols)
    {
      lowerEnabledProtocols.add(StaticUtils.toLowerCase(s));
    }

    ENABLED_SSL_PROTOCOLS.set(Collections.unmodifiableSet(enabledProtocols));
    LOWER_ENABLED_SSL_PROTOCOLS.set(Collections.unmodifiableSet(
         lowerEnabledProtocols));
  }
}
