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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.AggregatePostConnectProcessor;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPExtendedOperationException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SingleServerSet;
import com.unboundid.ldap.sdk.StartTLSPostConnectProcessor;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a set of test cases for the start administrative session
 * post-connect processor.
 */
public final class StartAdministrativeSessionPostConnectProcessorTestCase
     extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the post-connect processor when the extended
   * operation should be processed successfully.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulSession()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addExtendedOperationHandler(
         new StartAdministrativeSessionInMemoryExtendedOperationHandler(
              new ExtendedResult(1, ResultCode.SUCCESS, null, null, null,
                   null, null, null)));

    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer(config);
    ds.startListening();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());

    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
              new StartAdministrativeSessionPostConnectProcessor(
                   new StartAdministrativeSessionExtendedRequest(
                        "testSuccessfulSession", true)));

    assertNotNull(pool.getRootDSE());

    pool.close();

    ds.shutDown(true);
  }



  /**
   * Tests the behavior of the post-connect processor when the administrative
   * session should be successfully established before securing the connection
   * with StartTLS.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulSessionOverStartTLS()
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
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addExtendedOperationHandler(
         new StartAdministrativeSessionInMemoryExtendedOperationHandler(
              new ExtendedResult(1, ResultCode.SUCCESS, null, null, null,
                   null, null, null)));
    config.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("WithoutStartTLS"),
         InMemoryListenerConfig.createLDAPConfig("WithStartTLS", null,
              0, serverSSLUtil.createSSLSocketFactory()));

    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer(config);
    ds.startListening();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort("WithStartTLS"));

    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
              new AggregatePostConnectProcessor(
                   new StartAdministrativeSessionPostConnectProcessor(
                        new StartAdministrativeSessionExtendedRequest(
                             "testSuccessfulSession", true)),
                   new StartTLSPostConnectProcessor(
                        serverSSLUtil.createSSLSocketFactory())));

    assertNotNull(pool.getRootDSE());

    pool.close();

    ds.shutDown(true);
  }



  /**
   * Tests the behavior of the post-connect processor when the extended
   * operation should return an error result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedSession()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addExtendedOperationHandler(
         new StartAdministrativeSessionInMemoryExtendedOperationHandler(
              new ExtendedResult(1, ResultCode.UNWILLING_TO_PERFORM,
                   "Not gonna do it", null, null, null, null, null)));

    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer(config);
    ds.startListening();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());

    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
              new StartAdministrativeSessionPostConnectProcessor(
                   new StartAdministrativeSessionExtendedRequest(
                        "testSuccessfulSession", true)));

    try
    {
      pool.getRootDSE();
      fail("Expected an exception from the post-connect processor");
    }
    catch (final Exception e)
    {
      assertTrue(e instanceof LDAPExtendedOperationException);
      assertEquals(((LDAPExtendedOperationException) e).getResultCode(),
           ResultCode.UNWILLING_TO_PERFORM);
    }

    pool.close();

    ds.shutDown(true);
  }
}
