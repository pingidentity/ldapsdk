/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the set enabled protocols SSL
 * socket factory.
 */
public final class SetEnabledProtocolsSSLSocketFactoryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to create an unconnected socket.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateUnconnected()
         throws  Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    try
    {
      final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

      final SSLSocketFactory sslSocketFactory =
           sslUtil.createSSLSocketFactory();
      assertNotNull(sslSocketFactory);
      assertTrue(sslSocketFactory instanceof
           SetEnabledProtocolsAndCipherSuitesSSLSocketFactory);
      final SetEnabledProtocolsAndCipherSuitesSSLSocketFactory f =
           (SetEnabledProtocolsAndCipherSuitesSSLSocketFactory)
                sslSocketFactory;

      assertNotNull(f.getDefaultCipherSuites());

      assertNotNull(f.getSupportedCipherSuites());

      final Socket socket = f.createSocket();
      assertNotNull(socket);
      assertTrue(socket instanceof SetEnabledProtocolsAndCipherSuitesSocket);
      assertFalse(socket.isConnected());

      final SetEnabledProtocolsAndCipherSuitesSocket s =
           (SetEnabledProtocolsAndCipherSuitesSocket) socket;

      s.setTcpNoDelay(true);
      assertTrue(s.getTcpNoDelay());

      s.setSoLinger(true, 123);
      assertEquals(s.getSoLinger(), 123);

      s.setSoTimeout(0);
      assertEquals(s.getSoTimeout(), 0);

      s.setSendBufferSize(1234);
      s.getSendBufferSize();

      s.setReceiveBufferSize(5678);
      s.getReceiveBufferSize();

      s.setKeepAlive(true);
      assertTrue(s.getKeepAlive());

      s.setTrafficClass(s.getTrafficClass());

      s.setReuseAddress(true);
      assertTrue(s.getReuseAddress());

      s.setPerformancePreferences(2, 3, 1);

      s.setUseClientMode(true);
      assertTrue(s.getUseClientMode());

      s.setNeedClientAuth(false);
      assertFalse(s.getNeedClientAuth());

      s.setWantClientAuth(true);
      assertTrue(s.getWantClientAuth());

      s.setEnableSessionCreation(true);
      assertTrue(s.getEnableSessionCreation());

      final TestHandshakeCompletedListener listener =
           new TestHandshakeCompletedListener();
      s.addHandshakeCompletedListener(listener);
      s.removeHandshakeCompletedListener(listener);

      s.bind(null);
      assertTrue(s.isBound());

      s.connect(new InetSocketAddress("localhost", ds.getListenPort()));
      assertTrue(s.isConnected());

      assertNotNull(s.getSupportedCipherSuites());
      s.setEnabledCipherSuites(s.getEnabledCipherSuites());

      assertNotNull(s.getSupportedProtocols());
      s.setEnabledProtocols(s.getEnabledProtocols());

      assertNotNull(s.getInetAddress());
      assertNotNull(s.getLocalAddress());

      assertTrue(s.getPort() > 0);
      assertTrue(s.getPort() < 65536);

      assertTrue(s.getLocalPort() > 0);
      assertTrue(s.getLocalPort() < 65536);

      assertNotNull(s.getRemoteSocketAddress());
      assertNotNull(s.getLocalSocketAddress());

      s.startHandshake();

      assertNotNull(s.getSession());

      assertNull(s.getChannel());
      assertNotNull(s.getInputStream());
      assertNotNull(s.getOutputStream());

      assertNotNull(s.toString());

      try
      {
        s.sendUrgentData(1);
      }
      catch (final Exception e)
      {
        // This is expected for SSL sockets.
      }

      try
      {
        s.setOOBInline(false);
      }
      catch (final Exception e)
      {
        // This is expected for SSL sockets.
      }

      try
      {
        s.getOOBInline();
      }
      catch (final Exception e)
      {
        // This is expected for SSL sockets.
      }

      try
      {
        s.shutdownInput();
      }
      catch (final Exception e)
      {
        // This is expected for SSL sockets.
      }

      try
      {
        s.shutdownOutput();
      }
      catch (final Exception e)
      {
        // This is expected for SSL sockets.
      }

      s.close();

      s.isInputShutdown();
      s.isOutputShutdown();

      assertTrue(s.isClosed());
    }
    catch (final Exception e)
    {
      // Some old Java implementations don't support creating unconnected SSL
      // sockets, so we'll ignore this.
    }
  }



  /**
   * Tests the behavior when trying to create a socket using a string host and
   * int port.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateStringInt()
         throws  Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    final SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();
    assertNotNull(sslSocketFactory);
    assertTrue(sslSocketFactory instanceof
         SetEnabledProtocolsAndCipherSuitesSSLSocketFactory);
    final SetEnabledProtocolsAndCipherSuitesSSLSocketFactory f =
         (SetEnabledProtocolsAndCipherSuitesSSLSocketFactory) sslSocketFactory;

    assertNotNull(f.getDefaultCipherSuites());

    assertNotNull(f.getSupportedCipherSuites());

    final SSLSocket s =
         (SSLSocket) f.createSocket("127.0.0.1", ds.getListenPort());
    assertNotNull(s);
    assertTrue(s.isConnected());

    s.startHandshake();

    assertNotNull(s.getSession());

    s.close();
  }



  /**
   * Tests the behavior when trying to create a socket using a string host, an
   * int port, an InetAddress local address, and an int local port.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateStringIntInetInt()
         throws  Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    final SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();
    assertNotNull(sslSocketFactory);
    assertTrue(sslSocketFactory instanceof
         SetEnabledProtocolsAndCipherSuitesSSLSocketFactory);
    final SetEnabledProtocolsAndCipherSuitesSSLSocketFactory f =
         (SetEnabledProtocolsAndCipherSuitesSSLSocketFactory) sslSocketFactory;

    assertNotNull(f.getDefaultCipherSuites());

    assertNotNull(f.getSupportedCipherSuites());

    final SSLSocket s = (SSLSocket) f.createSocket("127.0.0.1",
         ds.getListenPort(), InetAddress.getLocalHost(), 0);
    assertNotNull(s);
    assertTrue(s.isConnected());

    s.startHandshake();

    assertNotNull(s.getSession());

    s.close();
  }



  /**
   * Tests the behavior when trying to create a socket using an InetAddress host
   * and int port.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateInetInt()
         throws  Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    final SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();
    assertNotNull(sslSocketFactory);
    assertTrue(sslSocketFactory instanceof
         SetEnabledProtocolsAndCipherSuitesSSLSocketFactory);
    final SetEnabledProtocolsAndCipherSuitesSSLSocketFactory f =
         (SetEnabledProtocolsAndCipherSuitesSSLSocketFactory) sslSocketFactory;

    assertNotNull(f.getDefaultCipherSuites());

    assertNotNull(f.getSupportedCipherSuites());

    final SSLSocket s = (SSLSocket) f.createSocket(InetAddress.getLocalHost(),
              ds.getListenPort());
    assertNotNull(s);
    assertTrue(s.isConnected());

    s.startHandshake();

    assertNotNull(s.getSession());

    s.close();
  }



  /**
   * Tests the behavior when trying to create a socket using an InetAddress
   * host, an int port, an InetAddress local address, and an int local port.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateInetIntInetInt()
         throws  Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    final SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();
    assertNotNull(sslSocketFactory);
    assertTrue(sslSocketFactory instanceof
         SetEnabledProtocolsAndCipherSuitesSSLSocketFactory);
    final SetEnabledProtocolsAndCipherSuitesSSLSocketFactory f =
         (SetEnabledProtocolsAndCipherSuitesSSLSocketFactory) sslSocketFactory;

    assertNotNull(f.getDefaultCipherSuites());

    assertNotNull(f.getSupportedCipherSuites());

    final SSLSocket s = (SSLSocket) f.createSocket(InetAddress.getLocalHost(),
         ds.getListenPort(), InetAddress.getLocalHost(), 0);
    assertNotNull(s);
    assertTrue(s.isConnected());

    s.startHandshake();

    assertNotNull(s.getSession());

    s.close();
  }
}
