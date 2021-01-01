/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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



import java.io.File;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.LDAPTestUtils;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first example in the {@code SSLUtil} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSLUtilExample1()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    InMemoryDirectoryServer ds = getTestDSWithSSL();
    final String serverAddress = "localhost";
    final int serverSSLPort = ds.getListenPort();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create an SSLUtil instance that is configured to trust any certificate,
    // and use it to create a socket factory.
    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();

    // Establish a secure connection using the socket factory.
    LDAPConnection connection = new LDAPConnection(sslSocketFactory);
    connection.connect(serverAddress, serverSSLPort);

    // Process operations using the connection....
    RootDSE rootDSE = connection.getRootDSE();

    connection.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    assertNotNull(rootDSE);
  }



  /**
   * Tests the second example in the {@code SSLUtil} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSLUtilExample2()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    assertTrue(serverKeyStore.exists());
    final String serverKeyStorePath = serverKeyStore.getAbsolutePath();
    final char[] serverKeyStorePIN = "password".toCharArray();

    final File serverTrustStore = new File(resourceDir, "server.truststore");
    assertTrue(serverTrustStore.exists());
    final String serverTrustStorePath = serverTrustStore.getAbsolutePath();

    final String trustStorePath = serverKeyStorePath;

    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStorePath, serverKeyStorePIN, "JKS",
              "server-cert"),
         new TrustStoreTrustManager(serverTrustStorePath));
    final SSLUtil clientSSLUtil = new SSLUtil(
         new TrustStoreTrustManager(trustStorePath));
    config.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("LDAP", // Listener name
              null, // Listen address. (null = listen on all interfaces)
              0, // Listen port (0 = automatically choose an available port)
              serverSSLUtil.createSSLSocketFactory())); // StartTLS factory

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();
    final String serverAddress = "localhost";
    final int serverPort = ds.getListenPort();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Establish a non-secure connection to the server.
    LDAPConnection connection = new LDAPConnection(serverAddress, serverPort);

    // Create an SSLUtil instance that is configured to trust certificates in
    // a specified trust store file, and use it to create an SSLContext that
    // will be used for StartTLS processing.
    SSLUtil sslUtil = new SSLUtil(new TrustStoreTrustManager(trustStorePath));
    SSLContext sslContext = sslUtil.createSSLContext();

    // Use the StartTLS extended operation to secure the connection.
    StartTLSExtendedRequest startTLSRequest =
         new StartTLSExtendedRequest(sslContext);
    ExtendedResult startTLSResult;
    try
    {
      startTLSResult = connection.processExtendedOperation(startTLSRequest);
    }
    catch (LDAPException le)
    {
      startTLSResult = new ExtendedResult(le);
    }
    LDAPTestUtils.assertResultCodeEquals(startTLSResult, ResultCode.SUCCESS);

    // Process operations using the connection....
    RootDSE rootDSE = connection.getRootDSE();

    connection.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    ds.shutDown(true);
    assertNotNull(rootDSE);
  }
}
