/*
 * Copyright 2023-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023-2025 Ping Identity Corporation
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
 * Copyright (C) 2023-2025 Ping Identity Corporation
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
package com.unboundid.util;



import java.net.InetSocketAddress;
import java.net.Proxy;
import javax.net.ssl.SSLSocketFactory;



/**
 * This class provides an implementation of a socket factory that can be used
 * to forward traffic through a SOCKSv4 or SOCKSv5 proxy server.  Because of
 * limitations in the Java support for SOCKS proxy servers, the following
 * constraints will be imposed:
 * <UL>
 *   <LI>
 *     Communication with the proxy server itself cannot be encrypted.  However,
 *     it is possible to encrypt all communication through the proxy server to
 *     the actual target server using TLS (by providing an
 *     {@code SSLSocketFactory} instance when creating the
 *     {@code SOCKSProxySocketFactory}), in which case the data will still be
 *     protected from the client to that target server, and anyone observing the
 *     communication between the client and the SOCKS proxy, or between the
 *     SOCKS proxy and the target server, would not be able to decipher that
 *     communication.
 *   </LI>
 *   <LI>
 *     This implementation only provides direct support for proxy servers that
 *     do not require authentication.  Although it may be possible to configure
 *     authentication using Java system properties, this implementation does not
 *     provide any direct support for authentication.
 *   </LI>
 * </UL>
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for establishing an LDAPS
 * connection through a SOCKS proxy server:
 * <PRE>
 *   final String socksProxyServerAddress = "socks-proxy.example.com";
 *   final int socksProxyServerPort = 1080;
 *   final int connectTimeoutMillis = 10_000;
 *
 *   final SSLUtil sslUtil =
 *        new SSLUtil(new TrustStoreTrustManager("/path/to/trust/store"));
 *   final SSLSocketFactory ldapsSocketFactory =
 *        sslUtil.createSSLSocketFactory();
 *
 *   final SOCKSProxySocketFactory socksProxySocketFactory =
 *        new SOCKSProxySocketFactory(socksProxyServerAddress,
 *             socksProxyServerPort, connectTimeoutMillis,
 *             ldapsSocketFactory);
 *
 *   final String ldapsServerAddress = "ds.example.com";
 *   final int ldapsServerPort = 636;
 *
 *   try (LDAPConnection conn = new LDAPConnection(socksProxySocketFactory,
 *        ldapsServerAddress, ldapsServerPort))
 *   {
 *     // Do something with the connection here.
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SOCKSProxySocketFactory
       extends ProxySocketFactory
{
  /**
   * Creates a new instance of this SOCKS socket factory with the provided
   * settings.  The resulting socket factory will provide support for
   * unencrypted LDAP communication.
   *
   * @param  socksProxyHost        The address of the SOCKS proxy server.  It
   *                               must not be {@code null}.
   * @param  socksProxyPort        The port on which the SOCKS proxy is
   *                               listening for new connections.
   * @param  connectTimeoutMillis  The maximum length of time in milliseconds to
   *                               wait for a connection to be established.  A
   *                               value that is less than or equal to zero
   *                               indicates that no explicit timeout will be
   *                               imposed.
   */
  public SOCKSProxySocketFactory(@NotNull final String socksProxyHost,
                                 final int socksProxyPort,
                                 final int connectTimeoutMillis)
  {
    this(socksProxyHost, socksProxyPort, connectTimeoutMillis, null);
  }



  /**
   * Creates a new instance of this SOCKS socket factory with the provided
   * settings.  The resulting socket factory may provide support for either
   * unencrypted LDAP communication (if the provided {@code sslSocketFactory}
   * value is {@code null}) or encrypted LDAPS communication (if the provided
   * {@code sslSocketFactory} value is non-{@code null}).
   *
   * @param  socksProxyHost        The address of the SOCKS proxy server.  It
   *                               must not be {@code null}.
   * @param  socksProxyPort        The port on which the SOCKS proxy is
   *                               listening for new connections.
   * @param  connectTimeoutMillis  The maximum length of time in milliseconds to
   *                               wait for a connection to be established.  A
   *                               value that is less than or equal to zero
   *                               indicates that no explicit timeout will be
   *                               imposed.
   * @param  sslSocketFactory      An SSL socket factory that should be used if
   *                               communication with the target LDAP server
   *                               should be encrypted with TLS.  It must be
   *                               {@code null} if communication should not be
   *                               encrypted, and it must not be {@code null} if
   *                               communication should be encrypted with TLS.
   */
  public SOCKSProxySocketFactory(@NotNull final String socksProxyHost,
              final int socksProxyPort,
              final int connectTimeoutMillis,
              @Nullable final SSLSocketFactory sslSocketFactory)
  {
    super(new Proxy(Proxy.Type.SOCKS,
                    new InetSocketAddress(socksProxyHost, socksProxyPort)),
         connectTimeoutMillis, sslSocketFactory);
  }
}
