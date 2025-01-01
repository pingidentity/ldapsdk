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



import java.net.InetAddress;
import java.net.Socket;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides test coverage for the {@code HTTPProxySocketFactory}
 * class.  Note, however, that since we can't guarantee the existence of an HTTP
 * proxy during unit tests, this class will not actually guarantee communication
 * with a server through a proxy.  Instead, it will merely attempt to get code
 * coverage.
 */
public final class HTTPProxySocketFactoryTestCase
       extends LDAPSDKTestCase
{
  // The port to use when trying to communicate with an HTTP proxy server.  This
  // port will not be in use on the local system, so communication attempts
  // should fail instantly.
  private int httpProxyPort;



  /**
   * Identifies a free port on the system that will not be in use so that
   * attempts to connect to it will fail immediately.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    // Start an in-memory directory server instance, figure out which port it's
    // listening on, and then shut it down.  That will ensure that attempts to
    // connect to that port will fail instantly.
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();
    httpProxyPort = ds.getListenPort();
    ds.shutDown(true);
  }



  /**
   * Tests the behavior when using a socket factory instance that was created
   * with the constructor that does not use an SSL socket factory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutSSLSocketFactory()
         throws Exception
  {
    final HTTPProxySocketFactory socketFactory = new HTTPProxySocketFactory(
         "127.0.0.1", httpProxyPort, 123);

    try
    {
      final Socket socket = socketFactory.createSocket();
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket = socketFactory.createSocket("127.0.0.1", 389);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket =
           socketFactory.createSocket("127.0.0.1", 389, null, 0);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket =
           socketFactory.createSocket(InetAddress.getByName("127.0.0.1"), 389);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket =
           socketFactory.createSocket(InetAddress.getByName("127.0.0.1"), 389,
                null, 0);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }
  }



  /**
   * Tests the behavior when using a socket factory instance that was created
   * with a {@code null} {@code SSLSocketFactory} instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithNullSSLSocketFactory()
         throws Exception
  {
    final HTTPProxySocketFactory socketFactory = new HTTPProxySocketFactory(
         "127.0.0.1", httpProxyPort, 123, null);

    try
    {
      final Socket socket = socketFactory.createSocket();
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket = socketFactory.createSocket("127.0.0.1", 636);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket =
           socketFactory.createSocket("127.0.0.1", 636, null, 0);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket =
           socketFactory.createSocket(InetAddress.getByName("127.0.0.1"), 636);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket =
           socketFactory.createSocket(InetAddress.getByName("127.0.0.1"), 636,
                null, 0);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }
  }



  /**
   * Tests the behavior when using a socket factory instance that was created
   * with a non-{@code null} {@code SSLSocketFactory} instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithNonNullSSLSocketFactory()
         throws Exception
  {
    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    final HTTPProxySocketFactory socketFactory = new HTTPProxySocketFactory(
         "127.0.0.1", httpProxyPort, 123, sslUtil.createSSLSocketFactory());

    try
    {
      final Socket socket = socketFactory.createSocket();
      fail("Should have gotten an UnsupportedOperationException");
    }
    catch (final UnsupportedOperationException e)
    {
      // This is expected when attempting to create an unconnected socket with
      // an SSLSocketFactory.
    }

    try
    {
      final Socket socket = socketFactory.createSocket("127.0.0.1", 636);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket =
           socketFactory.createSocket("127.0.0.1", 636, null, 0);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket =
           socketFactory.createSocket(InetAddress.getByName("127.0.0.1"), 636);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }

    try
    {
      final Socket socket =
           socketFactory.createSocket(InetAddress.getByName("127.0.0.1"), 636,
                null, 0);
      socket.close();
    }
    catch (final Exception e)
    {
      // This is expected when no HTTP proxy is actually available.
    }
  }
}
