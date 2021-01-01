/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a set of test cases that ensure that connections which
 * have been secured with StartTLS will behave correctly.
 */
public final class LDAPConnectionStartTLSTestCase
       extends LDAPSDKTestCase
{
  // The in-memory directory server instance that will be used for testing.
  private InMemoryDirectoryServer ds = null;



  /**
   * Sets up an in-memory directory server instance for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    // Get the paths to the client and server key and trust stores.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore = new File(resourceDir, "server.keystore");


    // Create SSLUtil objects for client and server use.
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustAllTrustManager());


    // Create a directory server instance with one listener that provides
    // unencrypted LDAP without StartTLS and another that supports unencrypted
    // LDAP with StartTLS.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("WithoutStartTLS"),
         InMemoryListenerConfig.createLDAPConfig("WithStartTLS", null,
              0, serverSSLUtil.createSSLSocketFactory()));

    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
  }



  /**
   * Cleans up after testing has completed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    ds.shutDown(true);
  }



  /**
   * Tests the behavior of an LDAP connection that is established, secured with
   * StartTLS, closed, and connected again.  The second connection should not
   * have StartTLS applied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectWithStartTLSAndReconnectWithoutStartTLS()
         throws Exception
  {
    final LDAPConnection conn =
         new LDAPConnection("localhost", ds.getListenPort("WithStartTLS"));
    assertNull(conn.getStartTLSRequest());

    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    final ExtendedResult startTLSResult = conn.processExtendedOperation(
         new StartTLSExtendedRequest(sslUtil.createSSLSocketFactory()));
    assertResultCodeEquals(startTLSResult, ResultCode.SUCCESS);
    assertNotNull(conn.getStartTLSRequest());

    conn.close();
    conn.connect("localhost", ds.getListenPort("WithStartTLS"));
    assertNull(conn.getStartTLSRequest());
    conn.close();
  }



  /**
   * Tests the behavior of an LDAP connection that is established, secured with
   * StartTLS, and then the reconnect method invoked.  The reconnected
   * connection should have StartTLS applied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReconnectWithStartTLS()
         throws Exception
  {
    final LDAPConnection conn =
         new LDAPConnection("localhost", ds.getListenPort("WithStartTLS"));
    assertNull(conn.getStartTLSRequest());

    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    final ExtendedResult startTLSResult = conn.processExtendedOperation(
         new StartTLSExtendedRequest(sslUtil.createSSLSocketFactory()));
    assertResultCodeEquals(startTLSResult, ResultCode.SUCCESS);
    assertNotNull(conn.getStartTLSRequest());

    conn.reconnect();
    assertNotNull(conn.getStartTLSRequest());
    conn.close();
  }



  /**
   * Tests the behavior of an LDAP connection that is established, secured with
   * StartTLS, and then is used to create a referral connection.  The referral
   * connection should have StartTLS applied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferralConnectionWithStartTLS()
         throws Exception
  {
    final LDAPConnection conn =
         new LDAPConnection("localhost", ds.getListenPort("WithStartTLS"));
    assertNull(conn.getStartTLSRequest());

    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    final ExtendedResult startTLSResult = conn.processExtendedOperation(
         new StartTLSExtendedRequest(sslUtil.createSSLSocketFactory()));
    assertResultCodeEquals(startTLSResult, ResultCode.SUCCESS);
    assertNotNull(conn.getStartTLSRequest());

    LDAPConnection referralConn = conn.getReferralConnection(
         new LDAPURL("ldap", "localhost", ds.getListenPort("WithStartTLS"),
              null, null, null, null),
         conn);
    assertNotNull(referralConn.getStartTLSRequest());
    referralConn.close();

    try
    {
      referralConn = conn.getReferralConnection(
           new LDAPURL("ldap", "localhost", ds.getListenPort("WithoutStartTLS"),
                null, null, null, null),
           conn);
      referralConn.close();
      fail("Expected an exception when trying to create a StartTLS-secured " +
           "referral connection to a server that doesn't support StartTLS");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    conn.close();
  }
}
