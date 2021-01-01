/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.NullTrustManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class tests the ability to test the in-memory directory server's ability
 * to request and require that the client provide a TLS certificate.
 */
public final class InMemoryDirectoryServerMutualAuthenticationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the getter and setter methods in the configuration for a generic
   * listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericListenerConfig()
         throws Exception
  {
    final LDAPListenerConfig config =
         new LDAPListenerConfig(0, new CannedResponseRequestHandler());

    assertFalse(config.requestClientCertificate());
    assertFalse(config.requireClientCertificate());

    config.setRequestClientCertificate(true);

    assertTrue(config.requestClientCertificate());
    assertFalse(config.requireClientCertificate());

    config.setRequireClientCertificate(true);

    assertTrue(config.requestClientCertificate());
    assertTrue(config.requireClientCertificate());

    config.setRequireClientCertificate(false);

    assertTrue(config.requestClientCertificate());
    assertFalse(config.requireClientCertificate());

    config.setRequestClientCertificate(false);

    assertFalse(config.requestClientCertificate());
    assertFalse(config.requireClientCertificate());
  }



  /**
   * Tests the getter and setter methods in the configuration for an in-memory
   * directory server listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInMemoryListenerConfig()
         throws Exception
  {
    InMemoryListenerConfig config = new InMemoryListenerConfig(
         "listenerName", null, 0, null, null, null);
    assertFalse(config.requestClientCertificate());
    assertFalse(config.requireClientCertificate());

    config = new InMemoryListenerConfig("listenerName", null, 0, null, null,
         null, false, false);
    assertFalse(config.requestClientCertificate());
    assertFalse(config.requireClientCertificate());

    config = new InMemoryListenerConfig("listenerName", null, 0, null, null,
         null, true, false);
    assertTrue(config.requestClientCertificate());
    assertFalse(config.requireClientCertificate());

    config = new InMemoryListenerConfig("listenerName", null, 0, null, null,
         null, true, true);
    assertTrue(config.requestClientCertificate());
    assertTrue(config.requireClientCertificate());
  }



  /**
   * Tests the behavior for an in-memory directory server configured to not
   * request client certificates when using SSL and the client certificate is
   * trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoNotRequestCertificateForSSLClientCertTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), false, false));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn = new LDAPConnection(
         clientSSLUtil.createSSLSocketFactory(), "127.0.0.1",
         ds.getListenPort()))
    {
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to not
   * request client certificates when using SSL and the client certificate is
   * not trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoNotRequestCertificateForSSLClientCertNotTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         NullTrustManager.getInstance());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), false, false));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();


    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn = new LDAPConnection(
         clientSSLUtil.createSSLSocketFactory(), "127.0.0.1",
         ds.getListenPort()))
    {
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to request
   * but not require client certificates when using SSL and no client
   * certificate is provided.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestCertificateForSSLClientNotProvided()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, false));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    try (LDAPConnection conn = new LDAPConnection(
         clientSSLUtil.createSSLSocketFactory(), "127.0.0.1",
         ds.getListenPort()))
    {
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to request
   * but not require client certificates when using SSL and the client
   * certificate is trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestCertificateForSSLClientCertTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, false));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn = new LDAPConnection(
         clientSSLUtil.createSSLSocketFactory(), "127.0.0.1",
         ds.getListenPort()))
    {
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to request
   * but not require client certificates when using SSL and the client
   * certificate is not trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestCertificateForSSLClientCertNotTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         NullTrustManager.getInstance());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, false));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();


    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn = new LDAPConnection(
         clientSSLUtil.createSSLSocketFactory(), "127.0.0.1",
         ds.getListenPort()))
    {
      conn.getRootDSE();
      fail("Expected an exception when presenting an untrusted certificate");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to require
   * client certificates when using SSL and no client certificate is provided.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequireCertificateForSSLClientNotProvided()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, true));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    try (LDAPConnection conn = new LDAPConnection(
         clientSSLUtil.createSSLSocketFactory(), "127.0.0.1",
         ds.getListenPort()))
    {
      conn.getRootDSE();
      fail("Expected an exception when not providing a required certificate");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to require
   * client certificates when using SSL and the client certificate is trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequireCertificateForSSLClientCertTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, true));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn = new LDAPConnection(
         clientSSLUtil.createSSLSocketFactory(), "127.0.0.1",
         ds.getListenPort()))
    {
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to require
   * client certificates when using SSL and the client certificate is not
   * trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequireCertificateForSSLClientCertNotTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         NullTrustManager.getInstance());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, true));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();


    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn = new LDAPConnection(
         clientSSLUtil.createSSLSocketFactory(), "127.0.0.1",
         ds.getListenPort()))
    {
      conn.getRootDSE();
      fail("Expected an exception when presenting an untrusted certificate");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to not
   * request client certificates when using StartTLS and the client certificate
   * is trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoNotRequestCertificateForStartTLSClientCertTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAP", null, 0, null,
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), false, false));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn =
              new LDAPConnection("127.0.0.1", ds.getListenPort()))
    {
      conn.processExtendedOperation(new StartTLSExtendedRequest(
           clientSSLUtil.createSSLSocketFactory()));
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to not
   * request client certificates when using StartTLS and the client certificate
   * is not trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoNotRequestCertificateForStartTLSClientCertNotTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         NullTrustManager.getInstance());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAP", null, 0, null,
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), false, false));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();


    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn =
              new LDAPConnection("127.0.0.1", ds.getListenPort()))
    {
      conn.processExtendedOperation(new StartTLSExtendedRequest(
           clientSSLUtil.createSSLSocketFactory()));
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to request
   * but not require client certificates when using StartTLS and no client
   * certificate is provided.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestCertificateForStartTLSClientNotProvided()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0, null,
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, false));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    try (LDAPConnection conn =
              new LDAPConnection("127.0.0.1", ds.getListenPort()))
    {
      conn.processExtendedOperation(new StartTLSExtendedRequest(
           clientSSLUtil.createSSLSocketFactory()));
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to request
   * but not require client certificates when using StartTLS and the client
   * certificate is trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestCertificateForStartTLSClientCertTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0, null,
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, false));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn =
              new LDAPConnection("127.0.0.1", ds.getListenPort()))
    {
      conn.processExtendedOperation(new StartTLSExtendedRequest(
           clientSSLUtil.createSSLSocketFactory()));
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to request
   * but not require client certificates when using StartTLS and the client
   * certificate is not trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestCertificateForStartTLSClientCertNotTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         NullTrustManager.getInstance());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0, null,
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, false));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();


    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn =
              new LDAPConnection("127.0.0.1", ds.getListenPort()))
    {
      conn.processExtendedOperation(new StartTLSExtendedRequest(
           clientSSLUtil.createSSLSocketFactory()));
      conn.getRootDSE();
      fail("Expected an exception when presenting an untrusted certificate");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to require
   * client certificates when using StartTLS and no client certificate is
   * provided.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequireCertificateForStartTLSClientNotProvided()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0, null,
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, true));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    try (LDAPConnection conn =
              new LDAPConnection("127.0.0.1", ds.getListenPort()))
    {
      conn.processExtendedOperation(new StartTLSExtendedRequest(
           clientSSLUtil.createSSLSocketFactory()));
      conn.getRootDSE();
      fail("Expected an exception when not providing a required certificate");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to require
   * client certificates when using StartTLS and the client certificate is
   * trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequireCertificateForStartTLSClientCertTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0, null,
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, true));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn =
              new LDAPConnection("127.0.0.1", ds.getListenPort()))
    {
      conn.processExtendedOperation(new StartTLSExtendedRequest(
           clientSSLUtil.createSSLSocketFactory()));
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior for an in-memory directory server configured to require
   * client certificates when using StartTLS and the client certificate is not
   * trusted.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequireCertificateForStartTLSClientCertNotTrusted()
         throws Exception
  {
    // Create an SSLUtil object for the server.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         NullTrustManager.getInstance());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0, null,
              serverSSLUtil.createSSLSocketFactory(),
              serverSSLUtil.createSSLSocketFactory(), true, true));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();


    // Create an SSLUtil object for the client.
    final File clientKeyStore = new File(resourceDir, "client.keystore");
    final SSLUtil clientSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(clientKeyStore, "password".toCharArray()),
         new TrustAllTrustManager());

    try (LDAPConnection conn =
              new LDAPConnection("127.0.0.1", ds.getListenPort()))
    {
      conn.processExtendedOperation(new StartTLSExtendedRequest(
           clientSSLUtil.createSSLSocketFactory()));
      conn.getRootDSE();
      fail("Expected an exception when presenting an untrusted certificate");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
    finally
    {
      ds.shutDown(true);
    }
  }
}

