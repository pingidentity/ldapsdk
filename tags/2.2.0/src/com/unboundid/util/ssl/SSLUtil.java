/*
 * Copyright 2008-2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2011 UnboundID Corp.
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



import java.security.GeneralSecurityException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;

import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Validator.*;



/**
 * This class provides a simple interface for creating {@code SSLContext} and
 * {@code SSLSocketFactory} instances, which may be used to create SSL-based
 * connections, or secure existing connections with StartTLS.
 * <BR><BR>
 * <H2>Example 1</H2>
 * The following example demonstrates the use of the SSL helper to create an
 * SSL-based LDAP connection that will blindly trust any certificate that the
 * server presents:
 * <PRE>
 *   SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
 *
 *   LDAPConnection connection =
 *        new LDAPConnection(sslUtil.createSSLSocketFactory());
 *   connection.connect("server.example.com", 636);
 * </PRE>
 * <BR>
 * <H2>Example 2</H2>
 * The following example demonstrates the use of the SSL helper to create a
 * non-secure LDAP connection and then use the StartTLS extended operation to
 * secure it.  It will use a trust store to determine whether to trust the
 * server certificate.
 * <PRE>
 *   LDAPConnection connection = new LDAPConnection();
 *   connection.connect("server.example.com", 389);
 *
 *   String trustStoreFile  = "/path/to/trust/store/file";
 *   SSLUtil sslUtil = new SSLUtil(new TrustStoreTrustManager(trustStoreFile));
 *
 *   ExtendedResult extendedResult = conn.processExtendedOperation(
 *        new StartTLSExtendedRequest(h.createSSLContext()));
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SSLUtil
{
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
   * trust managers.  It will use the "TLSv1" protocol and the default provider.
   *
   * @return  The created SSL context.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating or
   *                                    initializing the SSL context.
   */
  public SSLContext createSSLContext()
         throws GeneralSecurityException
  {
    return createSSLContext("TLSv1");
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
   * providers.  It will use the "TLSv1" protocol and the default provider.
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
   * manager providers.  It will use the "TLSv1" protocol and the default
   * provider.
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
   * manager providers.  It will use the "TLSv1" protocol and the default
   * provider.
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
   * manager providers.  It will use the "TLSv1" protocol and the default
   * provider.
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
}