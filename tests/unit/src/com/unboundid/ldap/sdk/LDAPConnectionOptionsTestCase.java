/*
 * Copyright 2008-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk;



import java.io.File;
import java.net.InetAddress;
import javax.net.ssl.SSLSocketFactory;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.SynchronizedSocketFactory;
import com.unboundid.util.SynchronizedSSLSocketFactory;
import com.unboundid.util.ssl.HostNameSSLSocketVerifier;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllSSLSocketVerifier;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;



/**
 * This class defines a set of test cases for the LDAPConnectionOptions class.
 */
public class LDAPConnectionOptionsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the default behavior for all connection options.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testDefaultSettings()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertFalse(opts.autoReconnect());
    assertTrue(opts.bindWithDNRequiresPassword());
    assertFalse(opts.followReferrals());
    assertEquals(opts.getReferralHopLimit(), 5);
    assertNull(opts.getReferralConnector());
    assertTrue(opts.useKeepAlive());
    assertTrue(opts.useLinger());
    assertEquals(opts.getLingerTimeoutSeconds(), 5);
    assertTrue(opts.useReuseAddress());
    assertFalse(opts.useSynchronousMode());
    assertTrue(opts.useTCPNoDelay());
    assertEquals(opts.getConnectTimeoutMillis(), 60000L);
    assertEquals(opts.getResponseTimeoutMillis(), 300000L);
    assertFalse(opts.abandonOnTimeout());
    assertEquals(opts.getMaxMessageSize(), (20 * 1024 * 1024));
    assertNull(opts.getDisconnectHandler());
    assertNull(opts.getUnsolicitedNotificationHandler());
    assertFalse(opts.captureConnectStackTrace());
    assertFalse(opts.useSchema());
    assertFalse(opts.usePooledSchema());
    assertEquals(opts.getReceiveBufferSize(), 0);
    assertEquals(opts.getSendBufferSize(), 0);

    final String vmVendor =
         StaticUtils.toLowerCase(System.getProperty("java.vm.vendor"));
    if (vmVendor.contains("sun microsystems") ||
        vmVendor.contains("oracle") ||
        vmVendor.contains("apple"))
    {
      assertTrue(opts.allowConcurrentSocketFactoryUse());
    }
    else
    {
      assertFalse(opts.allowConcurrentSocketFactoryUse());
    }

    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof TrustAllSSLSocketVerifier);
  }



  /**
   * Tests duplicate functionality.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testDuplicate()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    opts.setAutoReconnect(true);
    opts.setBindWithDNRequiresPassword(false);
    opts.setCaptureConnectStackTrace(true);
    opts.setConnectTimeoutMillis(1234);
    opts.setFollowReferrals(true);
    opts.setMaxMessageSize(1234);
    opts.setReferralHopLimit(10);
    opts.setReferralConnector(new TestReferralConnector());
    opts.setResponseTimeoutMillis(1234L);
    opts.setAbandonOnTimeout(true);
    opts.setDisconnectHandler(new TestDisconnectHandler());
    opts.setUnsolicitedNotificationHandler(
         new TestUnsolicitedNotificationHandler());
    opts.setUseKeepAlive(false);
    opts.setUseLinger(false, 1234);
    opts.setUseReuseAddress(false);
    opts.setUseTCPNoDelay(false);
    opts.setReceiveBufferSize(1234);
    opts.setSendBufferSize(1234);
    opts.setUseSynchronousMode(true);
    opts.setUseSchema(true);
    opts.setAllowConcurrentSocketFactoryUse(false);
    opts.setSSLSocketVerifier(new HostNameSSLSocketVerifier(true));

    final LDAPConnectionOptions dup = opts.duplicate();

    assertEquals(dup.autoReconnect(), opts.autoReconnect());
    assertEquals(dup.bindWithDNRequiresPassword(),
                 opts.bindWithDNRequiresPassword());
    assertEquals(dup.captureConnectStackTrace(),
                 opts.captureConnectStackTrace());
    assertEquals(dup.getConnectTimeoutMillis(), opts.getConnectTimeoutMillis());
    assertEquals(dup.followReferrals(), opts.followReferrals());
    assertEquals(dup.getReferralHopLimit(), opts.getReferralHopLimit());
    assertNotNull(dup.getReferralConnector());
    assertEquals(dup.getMaxMessageSize(), opts.getMaxMessageSize());
    assertEquals(dup.getResponseTimeoutMillis(),
                 opts.getResponseTimeoutMillis());
    assertEquals(dup.abandonOnTimeout(), opts.abandonOnTimeout());
    assertEquals(dup.getDisconnectHandler(), opts.getDisconnectHandler());
    assertEquals(dup.getUnsolicitedNotificationHandler(),
                 opts.getUnsolicitedNotificationHandler());
    assertEquals(dup.useKeepAlive(), opts.useKeepAlive());
    assertEquals(dup.useLinger(), opts.useLinger());
    assertEquals(dup.getLingerTimeoutSeconds(), opts.getLingerTimeoutSeconds());
    assertEquals(dup.useReuseAddress(), opts.useReuseAddress());
    assertEquals(dup.useTCPNoDelay(), opts.useTCPNoDelay());
    assertEquals(dup.getReceiveBufferSize(), 1234);
    assertEquals(dup.getSendBufferSize(), 1234);
    assertEquals(dup.useSynchronousMode(), opts.useSynchronousMode());
    assertEquals(dup.useSchema(), opts.useSchema());
    assertEquals(dup.usePooledSchema(), opts.usePooledSchema());
    assertEquals(dup.allowConcurrentSocketFactoryUse(),
         opts.allowConcurrentSocketFactoryUse());
    assertTrue(dup.getSSLSocketVerifier() instanceof HostNameSSLSocketVerifier);
  }



  /**
   * Tests autoReconnect functionality.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testAutoReconnect()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(LDAPConnectionOptions.DEFAULT_AUTO_RECONNECT, false);
    assertFalse(opts.autoReconnect());
    assertNotNull(opts.toString());

    opts.setAutoReconnect(true);
    assertTrue(opts.autoReconnect());
    assertNotNull(opts.toString());

    opts.setAutoReconnect(false);
    assertFalse(opts.autoReconnect());
    assertNotNull(opts.toString());
  }



  /**
   * Tests followReferrals functionality.
   */
  @Test()
  public void testFollowReferrals()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(LDAPConnectionOptions.DEFAULT_FOLLOW_REFERRALS, false);
    assertFalse(opts.followReferrals());
    assertNotNull(opts.toString());

    opts.setFollowReferrals(true);
    assertTrue(opts.followReferrals());
    assertNotNull(opts.toString());

    opts.setFollowReferrals(false);
    assertFalse(opts.followReferrals());
    assertNotNull(opts.toString());
  }



  /**
   * Tests referral hop limit functionality.
   */
  @Test()
  public void testReferralHopLimit()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(LDAPConnectionOptions.DEFAULT_REFERRAL_HOP_LIMIT, 5);
    assertEquals(opts.getReferralHopLimit(), 5);
    assertNotNull(opts.toString());

    opts.setReferralHopLimit(10);
    assertEquals(opts.getReferralHopLimit(), 10);
    assertNotNull(opts.toString());

    boolean caught = false;
    try
    {
      opts.setReferralHopLimit(0);
    }
    catch (final LDAPSDKUsageException ae)
    {
      caught = true;
    }
    assertTrue(caught, "Expected an error when trying to set a zero hop limit");

    caught = false;
    try
    {
      opts.setReferralHopLimit(-1);
    }
    catch (final LDAPSDKUsageException ae)
    {
      caught = true;
    }
    assertTrue(caught,
         "Expected an error when trying to set a negative hop limit");
  }



  /**
   * Tests behavior related to getting and setting the referral connector.
   */
  @Test()
  public void testReferralConnector()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertNull(opts.getReferralConnector());
    assertNotNull(opts.toString());

    opts.setReferralConnector(new TestReferralConnector());
    assertNotNull(opts.getReferralConnector());
    assertNotNull(opts.toString());

    opts.setReferralConnector(null);
    assertNull(opts.getReferralConnector());
    assertNotNull(opts.toString());
  }



  /**
   * Tests KeepAlive functionality.
   */
  @Test()
  public void testKeepAlive()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(LDAPConnectionOptions.DEFAULT_USE_KEEPALIVE, true);
    assertTrue(opts.useKeepAlive());
    assertNotNull(opts.toString());

    opts.setUseKeepAlive(false);
    assertFalse(opts.useKeepAlive());
    assertNotNull(opts.toString());

    opts.setUseKeepAlive(true);
    assertTrue(opts.useKeepAlive());
    assertNotNull(opts.toString());
  }



  /**
   * Tests linger functionality.
   */
  @Test()
  public void testLinger()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(LDAPConnectionOptions.DEFAULT_USE_LINGER, true);

    assertTrue(opts.useLinger());
    assertEquals(opts.getLingerTimeoutSeconds(),
         LDAPConnectionOptions.DEFAULT_LINGER_TIMEOUT_SECONDS);
    assertNotNull(opts.toString());

    opts.setUseLinger(false, 0);
    assertFalse(opts.useLinger());
    assertEquals(opts.getLingerTimeoutSeconds(), 0);
    assertNotNull(opts.toString());

    opts.setUseLinger(true, 3);
    assertTrue(opts.useLinger());
    assertEquals(opts.getLingerTimeoutSeconds(), 3);
    assertNotNull(opts.toString());
  }



  /**
   * Tests ReuseAddress functionality.
   */
  @Test()
  public void testReuseAddress()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(LDAPConnectionOptions.DEFAULT_USE_REUSE_ADDRESS, true);
    assertTrue(opts.useReuseAddress());
    assertNotNull(opts.toString());

    opts.setUseReuseAddress(false);
    assertFalse(opts.useReuseAddress());
    assertNotNull(opts.toString());

    opts.setUseReuseAddress(true);
    assertTrue(opts.useReuseAddress());
    assertNotNull(opts.toString());
  }



  /**
   * Tests TCP NoDelay functionality.
   */
  @Test()
  public void testTCPNoDelay()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(LDAPConnectionOptions.DEFAULT_USE_TCP_NODELAY, true);
    assertTrue(opts.useTCPNoDelay());
    assertNotNull(opts.toString());

    opts.setUseTCPNoDelay(false);
    assertFalse(opts.useTCPNoDelay());
    assertNotNull(opts.toString());

    opts.setUseTCPNoDelay(true);
    assertTrue(opts.useTCPNoDelay());
    assertNotNull(opts.toString());
  }



  /**
   * Tests capture connect stack trace functionality.
   */
  @Test()
  public void testCaptureConnectStackTrace()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(LDAPConnectionOptions.DEFAULT_CAPTURE_CONNECT_STACK_TRACE,
                 false);
    assertFalse(opts.captureConnectStackTrace());
    assertNotNull(opts.toString());

    opts.setCaptureConnectStackTrace(true);
    assertTrue(opts.captureConnectStackTrace());
    assertNotNull(opts.toString());

    opts.setCaptureConnectStackTrace(false);
    assertFalse(opts.captureConnectStackTrace());
    assertNotNull(opts.toString());
  }



  /**
   * Tests connect timeout functionality.
   */
  @Test()
  public void testConnectTimeout()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.getConnectTimeoutMillis(),
         LDAPConnectionOptions.DEFAULT_CONNECT_TIMEOUT_MILLIS);
    assertNotNull(opts.toString());

    opts.setConnectTimeoutMillis(0);
    assertEquals(opts.getConnectTimeoutMillis(), 0);
    assertNotNull(opts.toString());

    opts.setConnectTimeoutMillis(5000);
    assertEquals(opts.getConnectTimeoutMillis(), 5000);
    assertNotNull(opts.toString());
  }



  /**
   * Tests response timeout functionality.
   */
  @Test()
  public void testResponseTimeout()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.getResponseTimeoutMillis(),
                 LDAPConnectionOptions.DEFAULT_RESPONSE_TIMEOUT_MILLIS);
    assertNotNull(opts.toString());

    opts.setResponseTimeoutMillis(0L);
    assertEquals(opts.getResponseTimeoutMillis(), 0L);
    assertNotNull(opts.toString());

    opts.setResponseTimeoutMillis(5000L);
    assertEquals(opts.getResponseTimeoutMillis(), 5000L);
    assertNotNull(opts.toString());

    opts.setResponseTimeoutMillis(-1L);
    assertEquals(opts.getResponseTimeoutMillis(), 0L);
    assertNotNull(opts.toString());
  }



  /**
   * Tests abandon on timeout functionality.
   */
  @Test()
  public void testAbandonOnTimeout()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.abandonOnTimeout(),
         LDAPConnectionOptions.DEFAULT_ABANDON_ON_TIMEOUT);
    assertNotNull(opts.toString());

    opts.setAbandonOnTimeout(true);
    assertTrue(opts.abandonOnTimeout());
    assertNotNull(opts.toString());

    opts.setAbandonOnTimeout(false);
    assertFalse(opts.abandonOnTimeout());
    assertNotNull(opts.toString());
  }



  /**
   * Tests maximum message size functionality.
   */
  @Test()
  public void testMaxMessageSize()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.getMaxMessageSize(),
                 LDAPConnectionOptions.DEFAULT_MAX_MESSAGE_SIZE);
    assertNotNull(opts.toString());

    opts.setMaxMessageSize(0);
    assertEquals(opts.getMaxMessageSize(), 0);
    assertNotNull(opts.toString());

    opts.setMaxMessageSize(5000);
    assertEquals(opts.getMaxMessageSize(), 5000);
    assertNotNull(opts.toString());

    opts.setMaxMessageSize(-1);
    assertEquals(opts.getMaxMessageSize(), 0);
    assertNotNull(opts.toString());
  }



  /**
   * Tests disconnect handler functionality.
   */
  @Test()
  public void testDisconnectHandler()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertNull(opts.getDisconnectHandler());
    assertNotNull(opts.toString());

    opts.setDisconnectHandler(new TestDisconnectHandler());
    assertNotNull(opts.getDisconnectHandler());
    assertNotNull(opts.toString());

    opts.setDisconnectHandler(null);
    assertNull(opts.getDisconnectHandler());
    assertNotNull(opts.toString());
  }



  /**
   * Tests unsolicited notification handler functionality.
   */
  @Test()
  public void testUnsolicitedNotificationHandler()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertNull(opts.getUnsolicitedNotificationHandler());
    assertNotNull(opts.toString());

    opts.setUnsolicitedNotificationHandler(
         new TestUnsolicitedNotificationHandler());
    assertNotNull(opts.getUnsolicitedNotificationHandler());
    assertNotNull(opts.toString());

    opts.setUnsolicitedNotificationHandler(null);
    assertNull(opts.getUnsolicitedNotificationHandler());
    assertNotNull(opts.toString());
  }



  /**
   * Tests the ability to get and set send and receive buffer sizes.
   */
  @Test()
  public void testBufferSizes()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.getReceiveBufferSize(), 0);
    assertEquals(opts.getSendBufferSize(), 0);
    assertNotNull(opts.toString());

    opts.setReceiveBufferSize(1234);
    opts.setSendBufferSize(5678);
    assertNotNull(opts.toString());

    assertEquals(opts.getReceiveBufferSize(), 1234);
    assertEquals(opts.getSendBufferSize(), 5678);
    assertNotNull(opts.toString());

    opts.setReceiveBufferSize(-1234);
    opts.setSendBufferSize(-5678);
    assertNotNull(opts.toString());

    assertEquals(opts.getReceiveBufferSize(), 0);
    assertEquals(opts.getSendBufferSize(), 0);
    assertNotNull(opts.toString());

    opts.setReceiveBufferSize(0);
    opts.setSendBufferSize(0);
    assertNotNull(opts.toString());

    assertEquals(opts.getReceiveBufferSize(), 0);
    assertEquals(opts.getSendBufferSize(), 0);
    assertNotNull(opts.toString());
  }



  /**
   * Tests the ability to get and set the flag that controls synchronous mode.
   */
  @Test()
  public void testUseSynchronousMode()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertFalse(opts.useSynchronousMode());
    assertNotNull(opts.toString());

    opts.setUseSynchronousMode(true);
    assertTrue(opts.useSynchronousMode());
    assertNotNull(opts.toString());

    opts.setUseSynchronousMode(false);
    assertFalse(opts.useSynchronousMode());
    assertNotNull(opts.toString());
  }



  /**
   * Tests the ability to get and set the flag that controls whether to use
   * schema information when reading data from the server.
   */
  @Test()
  public void testUseSchema()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertFalse(opts.useSchema());
    assertFalse(opts.usePooledSchema());
    assertEquals(opts.getPooledSchemaTimeoutMillis(), 3600000L);
    assertNotNull(opts.toString());

    opts.setUseSchema(true);
    assertTrue(opts.useSchema());
    assertFalse(opts.usePooledSchema());
    assertEquals(opts.getPooledSchemaTimeoutMillis(), 3600000L);
    assertNotNull(opts.toString());

    opts.setUsePooledSchema(true);
    opts.setPooledSchemaTimeoutMillis(12345L);
    assertFalse(opts.useSchema());
    assertTrue(opts.usePooledSchema());
    assertEquals(opts.getPooledSchemaTimeoutMillis(), 12345L);
    assertNotNull(opts.toString());

    opts.setUseSchema(true);
    opts.setPooledSchemaTimeoutMillis(-12345L);
    assertTrue(opts.useSchema());
    assertFalse(opts.usePooledSchema());
    assertEquals(opts.getPooledSchemaTimeoutMillis(), 0L);
    assertNotNull(opts.toString());

    opts.setUseSchema(false);
    assertFalse(opts.useSchema());
    assertFalse(opts.usePooledSchema());
    assertEquals(opts.getPooledSchemaTimeoutMillis(), 0L);
    assertNotNull(opts.toString());
  }



  /**
   * Tests the ability to indicate whether the associated socket factory should
   * allow concurrent use of the socket factory by multiple threads.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowConcurrentSocketFactoryUse()
         throws Exception
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    opts.setAllowConcurrentSocketFactoryUse(false);
    assertFalse(opts.allowConcurrentSocketFactoryUse());

    LDAPConnection conn = new LDAPConnection(opts);
    assertTrue(conn.getSocketFactory() instanceof SynchronizedSocketFactory);

    conn = new LDAPConnection(sslUtil.createSSLSocketFactory(), opts);
    assertTrue(conn.getSocketFactory() instanceof SSLSocketFactory);
    assertTrue(conn.getSocketFactory() instanceof SynchronizedSSLSocketFactory);


    opts.setAllowConcurrentSocketFactoryUse(true);
    assertTrue(opts.allowConcurrentSocketFactoryUse());

    conn = new LDAPConnection(opts);
    assertFalse(conn.getSocketFactory() instanceof SynchronizedSocketFactory);

    conn = new LDAPConnection(sslUtil.createSSLSocketFactory(), opts);
    assertTrue(conn.getSocketFactory() instanceof SSLSocketFactory);
    assertFalse(conn.getSocketFactory()
         instanceof SynchronizedSSLSocketFactory);


    opts.setAllowConcurrentSocketFactoryUse(false);
    assertFalse(opts.allowConcurrentSocketFactoryUse());

    conn = new LDAPConnection(opts);
    assertTrue(conn.getSocketFactory() instanceof SynchronizedSocketFactory);

    conn = new LDAPConnection(sslUtil.createSSLSocketFactory(), opts);
    assertTrue(conn.getSocketFactory() instanceof SSLSocketFactory);
    assertTrue(conn.getSocketFactory() instanceof SynchronizedSSLSocketFactory);
  }



  /**
   * Tests methods related to SSL socket verifiers.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSLSocketVerifiers()
         throws Exception
  {
    // Create an in-memory directory server instance with support for SSL and
    // StartTLS.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final File serverTrustStore = new File(resourceDir, "server.truststore");

    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustStoreTrustManager(serverTrustStore));
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("LDAP",
              InetAddress.getLocalHost(), 0,
              serverSSLUtil.createSSLSocketFactory()),
         InMemoryListenerConfig.createLDAPSConfig("LDAPS",
              InetAddress.getLocalHost(), 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              clientSSLUtil.createSSLSocketFactory()));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof TrustAllSSLSocketVerifier);

    LDAPConnection conn = new LDAPConnection(
         clientSSLUtil.createSSLSocketFactory(), opts,
         ds.getListenAddress("LDAPS").getHostAddress(),
         ds.getListenPort("LDAPS"));
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = new LDAPConnection(opts,
         ds.getListenAddress("LDAP").getHostAddress(),
         ds.getListenPort("LDAP"));
    assertNotNull(conn.getRootDSE());
    assertResultCodeEquals(conn,
         new StartTLSExtendedRequest(clientSSLUtil.createSSLSocketFactory()),
         ResultCode.SUCCESS);
    assertNotNull(conn.getRootDSE());
    conn.close();


    opts.setSSLSocketVerifier(new HostNameSSLSocketVerifier(true));
    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof HostNameSSLSocketVerifier);

    try
    {
      conn = new LDAPConnection(clientSSLUtil.createSSLSocketFactory(), opts,
           ds.getListenAddress("LDAPS").getHostAddress(),
           ds.getListenPort("LDAPS"));
      conn.close();
      fail("Expected an exception due to hostname validation failure");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {
      conn.close();
    }

    try
    {
      conn = new LDAPConnection(opts,
           ds.getListenAddress("LDAP").getHostAddress(),
           ds.getListenPort("LDAP"));
      assertNotNull(conn.getRootDSE());
      conn.processExtendedOperation(
           new StartTLSExtendedRequest(clientSSLUtil.createSSLSocketFactory()));
      conn.close();
      fail("Expected an exception due to hostname validation failure");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {
      conn.close();
    }


    opts.setSSLSocketVerifier(null);
    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof TrustAllSSLSocketVerifier);


    conn = new LDAPConnection(clientSSLUtil.createSSLSocketFactory(), opts,
         ds.getListenAddress("LDAPS").getHostAddress(),
         ds.getListenPort("LDAPS"));
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = new LDAPConnection(opts,
         ds.getListenAddress("LDAP").getHostAddress(),
         ds.getListenPort("LDAP"));
    assertNotNull(conn.getRootDSE());
    assertResultCodeEquals(conn,
         new StartTLSExtendedRequest(clientSSLUtil.createSSLSocketFactory()),
         ResultCode.SUCCESS);
    assertNotNull(conn.getRootDSE());
    conn.close();

    ds.shutDown(true);
  }
}
