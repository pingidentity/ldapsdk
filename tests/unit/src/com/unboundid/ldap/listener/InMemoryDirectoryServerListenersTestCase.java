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

import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;



/**
 * This class provides a set of test cases for the in-memory directory server's
 * support for multiple listeners.
 */
public final class InMemoryDirectoryServerListenersTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the ability to use multiple listeners in the
   * in-memory directory server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleListeners()
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


    // Create a directory server instance with four listeners:
    // listener-1 -- Unencrypted LDAP without support for StartTLS
    // listener-2 -- Unencrypted LDAP with support for StartTLS
    // listener-3 -- SSL-encrypted LDAP
    // listener-4 -- SSL-encrypted LDAP
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("listener-1"),
         InMemoryListenerConfig.createLDAPConfig("listener-2", null,
              0, serverSSLUtil.createSSLSocketFactory()),
         InMemoryListenerConfig.createLDAPSConfig("listener-3",
              serverSSLUtil.createSSLServerSocketFactory()),
         InMemoryListenerConfig.createLDAPSConfig("listener-4",
              InetAddress.getLocalHost(), 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              clientSSLUtil.createSSLSocketFactory()));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);


    // Before starting the server, try establishing connections to it.  These
    // will obviously all fail.
    try
    {
      ds.getConnection();
      fail("Expected an exception when trying to get a connection with the " +
           "server offline and without specifying a listener");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      ds.getConnection("listener-1");
      fail("Expected an exception when trying to get a connection to " +
           "listener-1 with the server offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      ds.getConnection("listener-2");
      fail("Expected an exception when trying to get a connection to " +
           "listener-2 with the server offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      ds.getConnection("listener-3");
      fail("Expected an exception when trying to get a connection to " +
           "listener-3 with the server offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      ds.getConnection("listener-4");
      fail("Expected an exception when trying to get a connection to " +
           "listener-4 with the server offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      ds.getConnection("undefined");
      fail("Expected an exception when trying to get a connection to an " +
           "undefined listener with the server offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Verify the ability to obtain listen addresses, ports, and client socket
    // factories.
    assertNull(ds.getListenAddress());
    assertNull(ds.getListenAddress("listener-1"));
    assertNull(ds.getListenAddress("listener-2"));
    assertNull(ds.getListenAddress("listener-3"));
    assertNotNull(ds.getListenAddress("listener-4"));

    assertEquals(ds.getListenPort(), -1);
    assertEquals(ds.getListenPort("listener-1"), -1);
    assertEquals(ds.getListenPort("listener-2"), -1);
    assertEquals(ds.getListenPort("listener-3"), -1);
    assertEquals(ds.getListenPort("listener-4"), -1);

    assertNull(ds.getClientSocketFactory());
    assertNull(ds.getClientSocketFactory("listener-1"));
    assertNull(ds.getClientSocketFactory("listener-2"));
    assertNotNull(ds.getClientSocketFactory("listener-3"));
    assertNotNull(ds.getClientSocketFactory("listener-4"));


    // Start the server.
    ds.startListening();


    // Verify that we can now establish connections to the server for each of
    // the listeners.
    LDAPConnection conn = ds.getConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-1");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-2");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-3");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-4");
    assertNotNull(conn.getRootDSE());
    conn.close();

    try
    {
      ds.getConnection("undefined");
      fail("Expected an exception when trying to get a connection to an " +
           "undefined listener with the server online");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Verify the ability to obtain listen addresses, ports, and client socket
    // factories.
    assertNull(ds.getListenAddress());
    assertNull(ds.getListenAddress("listener-1"));
    assertNull(ds.getListenAddress("listener-2"));
    assertNull(ds.getListenAddress("listener-3"));
    assertNotNull(ds.getListenAddress("listener-4"));

    assertTrue(ds.getListenPort() > 0);
    final int listener1Port = ds.getListenPort("listener-1");
    final int listener2Port = ds.getListenPort("listener-2");
    final int listener3Port = ds.getListenPort("listener-3");
    final int listener4Port = ds.getListenPort("listener-4");
    assertTrue(listener1Port > 0);
    assertTrue(listener2Port > 0);
    assertTrue(listener3Port > 0);
    assertTrue(listener4Port > 0);
    assertTrue(listener1Port != listener2Port);
    assertTrue(listener1Port != listener3Port);
    assertTrue(listener1Port != listener4Port);
    assertTrue(listener2Port != listener3Port);
    assertTrue(listener2Port != listener4Port);
    assertTrue(listener3Port != listener4Port);


    assertNull(ds.getClientSocketFactory());
    assertNull(ds.getClientSocketFactory("listener-1"));
    assertNull(ds.getClientSocketFactory("listener-2"));
    assertNotNull(ds.getClientSocketFactory("listener-3"));
    assertNotNull(ds.getClientSocketFactory("listener-4"));


    // Start the server with it already running.  This should have no effect.
    ds.startListening();


    // Verify that we can still  establish connections to the server for each of
    // the listeners.
    conn = ds.getConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-1");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-2");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-3");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-4");
    assertNotNull(conn.getRootDSE());
    conn.close();

    try
    {
      ds.getConnection("undefined");
      fail("Expected an exception when trying to get a connection to an " +
           "undefined listener with the server online");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Stop all of the listeners.
    ds.shutDown(true);


    // Verify that we can no longer establish connections.
    try
    {
      ds.getConnection();
      fail("Expected an exception when trying to get a connection with the " +
           "server offline and without specifying a listener");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      ds.getConnection("listener-1");
      fail("Expected an exception when trying to get a connection to " +
           "listener-1 with the server offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      ds.getConnection("listener-2");
      fail("Expected an exception when trying to get a connection to " +
           "listener-2 with the server offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      ds.getConnection("listener-3");
      fail("Expected an exception when trying to get a connection to " +
           "listener-3 with the server offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      ds.getConnection("listener-4");
      fail("Expected an exception when trying to get a connection to " +
           "listener-4 with the server offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Start just the first and third listeners, along with another that isn't
    // defined.
    ds.startListening("listener-1");
    ds.startListening("listener-3");

    try
    {
      ds.startListening("undefined");
      fail("Expected an exception when trying to start an undefined listener");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Verify that we can establish connections to only those listeners.
    conn = ds.getConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-1");
    assertNotNull(conn.getRootDSE());
    conn.close();

    try
    {
      ds.getConnection("listener-2");
      fail("Expected an exception when trying to get a connection to " +
           "listener-2 with that listener offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    conn = ds.getConnection("listener-3");
    assertNotNull(conn.getRootDSE());
    conn.close();

    try
    {
      ds.getConnection("listener-4");
      fail("Expected an exception when trying to get a connection to " +
           "listener-4 with that listener offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Start listener 1 again.  This should have no effect.
    ds.startListening("listener-1");

    conn = ds.getConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-1");
    assertNotNull(conn.getRootDSE());
    conn.close();

    try
    {
      ds.getConnection("listener-2");
      fail("Expected an exception when trying to get a connection to " +
           "listener-2 with that listener offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    conn = ds.getConnection("listener-3");
    assertNotNull(conn.getRootDSE());
    conn.close();

    try
    {
      ds.getConnection("listener-4");
      fail("Expected an exception when trying to get a connection to " +
           "listener-4 with that listener offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Stop listener 1 so that 3 will be the only one still running.  And
    // for the heck of it, stop listener 2 again, and one that doesn't exist.
    ds.shutDown("listener-1", true);
    ds.shutDown("listener-2", true);
    ds.shutDown("undefined", true);

    conn = ds.getConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    try
    {
      ds.getConnection("listener-1");
      fail("Expected an exception when trying to get a connection to " +
           "listener-1 with that listener offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      ds.getConnection("listener-2");
      fail("Expected an exception when trying to get a connection to " +
           "listener-2 with that listener offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    conn = ds.getConnection("listener-3");
    assertNotNull(conn.getRootDSE());
    conn.close();

    try
    {
      ds.getConnection("listener-4");
      fail("Expected an exception when trying to get a connection to " +
           "listener-4 with that listener offline");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Restart the server.  Verify that all of the listeners are back online.
    ds.restartServer();

    conn = ds.getConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-1");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-2");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-3");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-4");
    assertNotNull(conn.getRootDSE());
    conn.close();


    // Restart each of the listeners and verify that things still work.
    ds.restartListener("listener-1");
    ds.restartListener("listener-2");
    ds.restartListener("listener-3");
    ds.restartListener("listener-4");

    conn = ds.getConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-1");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-2");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-3");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-4");
    assertNotNull(conn.getRootDSE());
    conn.close();


    // Stop the server and restart it and verify that things still work.
    ds.shutDown(true);
    ds.restartServer();

    conn = ds.getConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-1");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-2");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-3");
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-4");
    assertNotNull(conn.getRootDSE());
    conn.close();


    // Verify the ability to obtain listen addresses, ports, and client socket
    // factories.
    assertNull(ds.getListenAddress());
    assertNull(ds.getListenAddress("listener-1"));
    assertNull(ds.getListenAddress("listener-2"));
    assertNull(ds.getListenAddress("listener-3"));
    assertNotNull(ds.getListenAddress("listener-4"));

    assertTrue(ds.getListenPort() > 0);
    assertEquals(ds.getListenPort("listener-1"), listener1Port);
    assertEquals(ds.getListenPort("listener-2"), listener2Port);
    assertEquals(ds.getListenPort("listener-3"), listener3Port);
    assertEquals(ds.getListenPort("listener-4"), listener4Port);


    assertNull(ds.getClientSocketFactory());
    assertNull(ds.getClientSocketFactory("listener-1"));
    assertNull(ds.getClientSocketFactory("listener-2"));
    assertNotNull(ds.getClientSocketFactory("listener-3"));
    assertNotNull(ds.getClientSocketFactory("listener-4"));


    // Verify that we can establish a StartTLS connection on the second
    // listener but not on the first.
    conn = new LDAPConnection("127.0.0.1", listener1Port);
    assertNotNull(conn.getRootDSE());

    try
    {
      final ExtendedResult startTLSResult = conn.processExtendedOperation(
           new StartTLSExtendedRequest(clientSSLUtil.createSSLContext()));
      assertFalse(startTLSResult.getResultCode() == ResultCode.SUCCESS);
    }
    catch (final LDAPException le)
    {
      // This is an acceptable result.
    }
    conn.close();

    conn = new LDAPConnection("127.0.0.1", listener2Port);
    assertNotNull(conn.getRootDSE());

    final ExtendedResult startTLSResult = conn.processExtendedOperation(
         new StartTLSExtendedRequest(clientSSLUtil.createSSLContext()));
    assertEquals(startTLSResult.getResultCode(), ResultCode.SUCCESS);
    assertNotNull(conn.getRootDSE());
    conn.close();


    // Shut down the server.
    ds.shutDown(true);
  }



  /**
   * Tests a configuration with multiple listeners that attempt to use
   * conflicting port numbers.  In this case, it should be possible to start one
   * listener but not the other.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConflictingPorts()
         throws Exception
  {
    // Create a server instance with a single listener using an
    // automatically-chosen listen port and figure out what port that is.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("listener-1"));

    InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final int listenPort = ds.getListenPort();
    ds.shutDown(true);


    // Create a new server with multiple listeners trying to use that same
    // port.
    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("listener-1", listenPort),
         InMemoryListenerConfig.createLDAPConfig("listener-2", listenPort));

    ds = new InMemoryDirectoryServer(cfg);


    // Verify that the attempt to start the server will throw an exception.
    try
    {
      ds.startListening();
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // However, verify that the first listener was actually started.
    LDAPConnection conn = ds.getConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = ds.getConnection("listener-1");
    assertNotNull(conn.getRootDSE());
    conn.close();

    try
    {
      ds.getConnection("listener-2");
      fail("Expected an exception when trying to get a connection to " +
           "listener 2");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Shut down the first listener and verify that we can now star the second.
    ds.shutDown("listener-1", true);
    ds.startListening("listener-2");

    conn = ds.getConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    try
    {
      ds.getConnection("listener-1");
      fail("Expected an exception when trying to get a connection to " +
           "listener 1");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    conn = ds.getConnection("listener-2");
    assertNotNull(conn.getRootDSE());
    conn.close();


    // Verify that we cannot restart listener 1.
    try
    {
      ds.startListening("listener-1");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    ds.shutDown(true);
  }
}
