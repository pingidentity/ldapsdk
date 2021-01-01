/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.io.File;
import java.net.InetAddress;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;



/**
 * This class provides a set of test cases for the InMemoryListenerConfig class.
 */
public final class InMemoryListenerConfigTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for configurations created using the constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor()
         throws Exception
  {
    // Get the paths to the client and server key and trust stores.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final File serverTrustStore = new File(resourceDir, "server.truststore");


    // Create SSLUtil objects for client and server use.
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustStoreTrustManager(serverTrustStore));

    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    InMemoryListenerConfig c = new InMemoryListenerConfig("test1", null,
         0, null, null, null);

    assertEquals(c.getListenerName(), "test1");
    assertNull(c.getListenAddress());
    assertEquals(c.getListenPort(), 0);
    assertNull(c.getServerSocketFactory());
    assertNull(c.getClientSocketFactory());
    assertNull(c.getStartTLSSocketFactory());
    assertNotNull(c.toString());


    c = new InMemoryListenerConfig("test2", InetAddress.getLocalHost(), 1234,
         serverSSLUtil.createSSLServerSocketFactory(),
         clientSSLUtil.createSSLSocketFactory(), null);

    assertEquals(c.getListenerName(), "test2");
    assertNotNull(c.getListenAddress());
    assertEquals(c.getListenPort(), 1234);
    assertNotNull(c.getServerSocketFactory());
    assertNotNull(c.getClientSocketFactory());
    assertNull(c.getStartTLSSocketFactory());
    assertNotNull(c.toString());


    c = new InMemoryListenerConfig("test3", null, 5678, null, null,
         serverSSLUtil.createSSLSocketFactory());

    assertEquals(c.getListenerName(), "test3");
    assertNull(c.getListenAddress());
    assertEquals(c.getListenPort(), 5678);
    assertNull(c.getServerSocketFactory());
    assertNull(c.getClientSocketFactory());
    assertNotNull(c.getStartTLSSocketFactory());
    assertNotNull(c.toString());

    try
    {
      new InMemoryListenerConfig(null, null, 0, null, null, null);
      fail("Expected an exception with a null listener name");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      new InMemoryListenerConfig("", null, 0, null, null, null);
      fail("Expected an exception with an empty listener name");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      new InMemoryListenerConfig("test", null, -1, null, null, null);
      fail("Expected an exception with a negative port");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      new InMemoryListenerConfig("test", null, 12345678, null, null, null);
      fail("Expected an exception with port that is too large");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Provides coverage for the createLDAPConfig method that takes a name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLDAPConfigName()
         throws Exception
  {
    final InMemoryListenerConfig c =
         InMemoryListenerConfig.createLDAPConfig("test");

    assertNotNull(c);
    assertEquals(c.getListenerName(), "test");
    assertNull(c.getListenAddress());
    assertEquals(c.getListenPort(), 0);
    assertNull(c.getServerSocketFactory());
    assertNull(c.getClientSocketFactory());
    assertNull(c.getStartTLSSocketFactory());
    assertNotNull(c.toString());
  }



  /**
   * Provides coverage for the createLDAPConfig method that takes a name and
   * port.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLDAPConfigNamePort()
         throws Exception
  {
    final InMemoryListenerConfig c =
         InMemoryListenerConfig.createLDAPConfig("test", 389);

    assertNotNull(c);
    assertEquals(c.getListenerName(), "test");
    assertNull(c.getListenAddress());
    assertEquals(c.getListenPort(), 389);
    assertNull(c.getServerSocketFactory());
    assertNull(c.getClientSocketFactory());
    assertNull(c.getStartTLSSocketFactory());
    assertNotNull(c.toString());
  }



  /**
   * Provides coverage for the createLDAPConfig method that takes a name,
   * address, port, and StartTLS socket factory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLDAPConfigNameAddressPortFactory()
         throws Exception
  {
    // Get the paths to the client and server key and trust stores.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final File serverTrustStore = new File(resourceDir, "server.truststore");


    // Create SSLUtil objects for client and server use.
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustStoreTrustManager(serverTrustStore));

    final InMemoryListenerConfig c =
         InMemoryListenerConfig.createLDAPConfig("test",
              InetAddress.getLocalHost(), 389,
              serverSSLUtil.createSSLSocketFactory());

    assertNotNull(c);
    assertEquals(c.getListenerName(), "test");
    assertNotNull(c.getListenAddress());
    assertEquals(c.getListenPort(), 389);
    assertNull(c.getServerSocketFactory());
    assertNull(c.getClientSocketFactory());
    assertNotNull(c.getStartTLSSocketFactory());
    assertNotNull(c.toString());
  }



  /**
   * Provides coverage for the createLDAPSConfig method that takes a name and
   * server socket factory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLDAPSConfigNameServerFactory()
         throws Exception
  {
    // Get the paths to the client and server key and trust stores.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final File serverTrustStore = new File(resourceDir, "server.truststore");


    // Create SSLUtil objects for client and server use.
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustStoreTrustManager(serverTrustStore));

    final InMemoryListenerConfig c =
         InMemoryListenerConfig.createLDAPSConfig("test",
              serverSSLUtil.createSSLServerSocketFactory());

    assertNotNull(c);
    assertEquals(c.getListenerName(), "test");
    assertNull(c.getListenAddress());
    assertEquals(c.getListenPort(), 0);
    assertNotNull(c.getServerSocketFactory());
    assertNotNull(c.getClientSocketFactory());
    assertNull(c.getStartTLSSocketFactory());
    assertNotNull(c.toString());
  }



  /**
   * Provides coverage for the createLDAPSConfig method that takes a name, port,
   * and server socket factory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLDAPSConfigNamePortServerFactory()
         throws Exception
  {
    // Get the paths to the client and server key and trust stores.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final File serverTrustStore = new File(resourceDir, "server.truststore");


    // Create SSLUtil objects for client and server use.
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustStoreTrustManager(serverTrustStore));

    final InMemoryListenerConfig c =
         InMemoryListenerConfig.createLDAPSConfig("test", 636,
              serverSSLUtil.createSSLServerSocketFactory());

    assertNotNull(c);
    assertEquals(c.getListenerName(), "test");
    assertNull(c.getListenAddress());
    assertEquals(c.getListenPort(), 636);
    assertNotNull(c.getServerSocketFactory());
    assertNotNull(c.getClientSocketFactory());
    assertNull(c.getStartTLSSocketFactory());
    assertNotNull(c.toString());
  }



  /**
   * Provides coverage for the createLDAPSConfig method that takes a name,
   * address, port, server socket factory, and client socket factory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLDAPSConfigNameAddressPortServerAndClientFactory()
         throws Exception
  {
    // Get the paths to the client and server key and trust stores.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final File serverTrustStore = new File(resourceDir, "server.truststore");


    // Create SSLUtil objects for client and server use.
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustStoreTrustManager(serverTrustStore));

    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    final InMemoryListenerConfig c =
         InMemoryListenerConfig.createLDAPSConfig("test",
              InetAddress.getLocalHost(), 636,
              serverSSLUtil.createSSLServerSocketFactory(),
              clientSSLUtil.createSSLSocketFactory());

    assertNotNull(c);
    assertEquals(c.getListenerName(), "test");
    assertNotNull(c.getListenAddress());
    assertEquals(c.getListenPort(), 636);
    assertNotNull(c.getServerSocketFactory());
    assertNotNull(c.getClientSocketFactory());
    assertNull(c.getStartTLSSocketFactory());
    assertNotNull(c.toString());


    try
    {
      InMemoryListenerConfig.createLDAPSConfig("test", null, 0, null, null);
      fail("Expected an exception with a null server socket factory");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }
}
